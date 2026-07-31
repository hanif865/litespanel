"""Git Version Control — manage git repositories under the account's home.

Repositories are created either empty (git init) or by cloning a remote URL,
always inside a folder under one of the account's sites. The provider performs
the real git work on the host (running as the account's system user); this
router records the panel's knowledge of the repo.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import PurePosixPath

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Domain, GitRepo, User
from ..providers import get_provider
from ..security import current_user
from ..web import templates

router = APIRouter(prefix="/git", tags=["git"])

# Repository folder name: a plain slug (no path separators).
_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$")
# Only http(s):// and git:// remotes — never a local path or ssh/file scheme
# the user could point at arbitrary host files.
_URL_RE = re.compile(r"^(https?|git)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _repo_path(docroot: str, name: str) -> str | None:
    """Resolve the repo working tree under the site's docroot, no traversal."""
    parts = PurePosixPath(name.replace("\\", "/")).parts
    if len(parts) != 1 or parts[0] in ("..", "") or ":" in parts[0]:
        return None
    return str(PurePosixPath(docroot) / parts[0])


@router.get("")
def list_git(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    repos = db.scalars(
        select(GitRepo).where(GitRepo.owner_id == user.id).order_by(GitRepo.name)
    ).all()
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)
    output = request.session.pop("git_output", None)
    return templates.TemplateResponse(
        request,
        "git.html",
        {"user": user, "repos": repos, "domains": domains,
         "active": "git", "flash": flash, "output": output},
    )


@router.post("/create")
def create_git(
    request: Request,
    name: str = Form(...),
    domain_id: int = Form(...),
    clone_url: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        _flash(request, "❌ Domain not found.")
        return RedirectResponse("/git", status_code=303)

    name = name.strip()
    if not _NAME_RE.match(name):
        _flash(request, "❌ Invalid repository name (letters, digits, dot, dash, underscore).")
        return RedirectResponse("/git", status_code=303)

    clone_url = clone_url.strip()
    if clone_url and not _URL_RE.match(clone_url):
        _flash(request, "❌ Clone URL must be an http(s):// or git:// address.")
        return RedirectResponse("/git", status_code=303)

    path = _repo_path(domain.docroot, name)
    if path is None:
        _flash(request, "❌ Repository name may not contain path separators.")
        return RedirectResponse("/git", status_code=303)

    if db.scalar(select(GitRepo).where(GitRepo.owner_id == user.id, GitRepo.path == path)):
        _flash(request, f"❌ A repository already exists at {path}.")
        return RedirectResponse("/git", status_code=303)

    try:
        get_provider().create_git_repo(path, user.system_user, clone_url or None)
    except Exception as exc:  # surface git failure to the user, don't 500
        _flash(request, f"❌ Git error: {exc}")
        return RedirectResponse("/git", status_code=303)

    db.add(GitRepo(owner_id=user.id, name=name, path=path,
                   clone_url=clone_url or None))
    db.commit()
    _flash(request, f"✅ Repository '{name}' {'cloned' if clone_url else 'created'}.")
    return RedirectResponse("/git", status_code=303)


@router.post("/{repo_id}/pull")
def pull_git(
    request: Request,
    repo_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    repo = db.get(GitRepo, repo_id)
    if repo is None or repo.owner_id != user.id:
        _flash(request, "❌ Repository not found.")
        return RedirectResponse("/git", status_code=303)
    try:
        out = get_provider().git_pull(repo.path)
    except Exception as exc:
        _flash(request, f"❌ Git error: {exc}")
        return RedirectResponse("/git", status_code=303)
    repo.last_pull_at = datetime.now(timezone.utc)
    db.commit()
    request.session["git_output"] = {"repo": repo.name, "text": out}
    _flash(request, f"⤵️ Pulled '{repo.name}'.")
    return RedirectResponse("/git", status_code=303)


@router.post("/{repo_id}/delete")
def delete_git(
    request: Request,
    repo_id: int,
    remove_files: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    repo = db.get(GitRepo, repo_id)
    if repo is None or repo.owner_id != user.id:
        _flash(request, "❌ Repository not found.")
        return RedirectResponse("/git", status_code=303)
    if remove_files == "on":
        try:
            get_provider().delete_git_repo(repo.path)
        except Exception as exc:
            _flash(request, f"❌ Git error: {exc}")
            return RedirectResponse("/git", status_code=303)
    name = repo.name
    db.delete(repo)
    db.commit()
    _flash(request, f"🗑️ Repository '{name}' removed{' with its files' if remove_files == 'on' else ''}.")
    return RedirectResponse("/git", status_code=303)
