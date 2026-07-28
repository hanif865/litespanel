"""File manager — browse/upload/edit/delete within a domain's docroot.

Every path is resolved and checked to stay inside the selected domain's
document root, so a crafted "../.." can never escape the sandbox.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Domain, User
from ..providers import get_provider
from ..security import current_user
from ..web import human_size, templates

router = APIRouter(prefix="/files", tags=["files"])

# Files larger than this aren't offered for inline editing.
MAX_EDIT_BYTES = 512 * 1024
TEXT_SUFFIXES = {
    ".html", ".htm", ".css", ".js", ".json", ".txt", ".md", ".php",
    ".py", ".xml", ".conf", ".env", ".ini", ".yml", ".yaml", ".htaccess",
}


def _flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def _owned_domain(db: Session, user: User, domain_id: int) -> Domain:
    domain = db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain


def _own(domain: Domain, path: Path) -> None:
    """Hand a newly created file/folder to the site's isolated account user."""
    sysuser = domain.owner.system_user
    if sysuser:
        get_provider().set_owner(path, sysuser)


def _safe_join(docroot: Path, rel: str) -> Path:
    """Resolve `rel` under `docroot`, refusing anything that escapes it."""
    root = docroot.resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise HTTPException(status_code=400, detail="Path escapes the site root.")
    return target


@router.get("")
def browse(
    request: Request,
    domain_id: int | None = None,
    path: str = "",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domains = db.scalars(
        select(Domain).where(Domain.owner_id == user.id).order_by(Domain.name)
    ).all()
    flash = request.session.pop("flash", None)

    ctx: dict = {"user": user, "domains": domains, "active": "files", "flash": flash,
                 "selected": None, "entries": [], "path": "", "parent": None}

    if not domains:
        return templates.TemplateResponse(request, "files.html", ctx)

    domain = _owned_domain(db, user, domain_id) if domain_id else domains[0]
    docroot = Path(domain.docroot)
    docroot.mkdir(parents=True, exist_ok=True)
    current = _safe_join(docroot, path)
    if not current.is_dir():
        current = docroot
        path = ""

    entries = []
    for child in sorted(current.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        stat = child.stat()
        rel = child.relative_to(docroot.resolve()).as_posix()
        entries.append({
            "name": child.name,
            "rel": rel,
            "is_dir": child.is_dir(),
            "size": stat.st_size,
            "editable": child.is_file()
            and stat.st_size <= MAX_EDIT_BYTES
            and (child.suffix.lower() in TEXT_SUFFIXES or child.name in TEXT_SUFFIXES),
        })

    parent = None
    if path:
        parent = str(Path(path).parent.as_posix())
        parent = "" if parent == "." else parent

    ctx.update({"selected": domain, "entries": entries, "path": path, "parent": parent})
    return templates.TemplateResponse(request, "files.html", ctx)


@router.post("/upload")
async def upload(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    dest_dir = _safe_join(Path(domain.docroot), path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(file.filename or "upload.bin").name  # strip any path parts
    dest = _safe_join(dest_dir, filename)
    with dest.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            out.write(chunk)
    _own(domain, dest)
    _flash(request, f"⬆️ Uploaded {filename} ({human_size(dest.stat().st_size)}).")
    return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)


@router.post("/mkdir")
def mkdir(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    folder = Path(name).name
    target = _safe_join(_safe_join(Path(domain.docroot), path), folder)
    target.mkdir(parents=True, exist_ok=True)
    _own(domain, target)
    _flash(request, f"📁 Folder '{folder}' created.")
    return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)


@router.get("/edit")
def edit_form(
    request: Request,
    domain_id: int,
    path: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    target = _safe_join(Path(domain.docroot), path)
    if not target.is_file() or target.stat().st_size > MAX_EDIT_BYTES:
        raise HTTPException(status_code=400, detail="File is not editable.")
    content = target.read_text(encoding="utf-8", errors="replace")
    return templates.TemplateResponse(
        request,
        "edit.html",
        {"user": user, "domain": domain, "path": path, "content": content, "active": "files"},
    )


@router.post("/edit")
def edit_save(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(...),
    content: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    target = _safe_join(Path(domain.docroot), path)
    # Normalize CRLF from the browser textarea to LF.
    target.write_text(content.replace("\r\n", "\n"), encoding="utf-8")
    _flash(request, f"💾 Saved {Path(path).name}.")
    parent = Path(path).parent.as_posix()
    parent = "" if parent == "." else parent
    return RedirectResponse(f"/files?domain_id={domain_id}&path={parent}", status_code=303)


@router.get("/download")
def download(
    domain_id: int,
    path: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    target = _safe_join(Path(domain.docroot), path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File not found.")
    return FileResponse(target, filename=target.name)


@router.post("/delete")
def delete_entry(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    target_rel: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    import shutil

    domain = _owned_domain(db, user, domain_id)
    target = _safe_join(Path(domain.docroot), target_rel)
    root = Path(domain.docroot).resolve()
    if target == root:
        _flash(request, "❌ Cannot delete the site root.")
    elif target.is_dir():
        shutil.rmtree(target, ignore_errors=True)
        _flash(request, f"🗑️ Deleted folder '{target.name}'.")
    elif target.exists():
        target.unlink()
        _flash(request, f"🗑️ Deleted '{target.name}'.")
    return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)


@router.post("/newfile")
def new_file(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    filename = Path(name).name
    if not filename:
        _flash(request, "❌ Enter a file name.")
        return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)
    target = _safe_join(_safe_join(Path(domain.docroot), path), filename)
    if target.exists():
        _flash(request, f"❌ '{filename}' already exists.")
    else:
        target.touch()
        _own(domain, target)
        _flash(request, f"📄 File '{filename}' created.")
    return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)


@router.post("/rename")
def rename_entry(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    target_rel: str = Form(...),
    new_name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    src = _safe_join(Path(domain.docroot), target_rel)
    dest = _safe_join(src.parent, Path(new_name).name)
    if not src.exists():
        _flash(request, "❌ Item not found.")
    elif dest.exists():
        _flash(request, f"❌ '{dest.name}' already exists.")
    else:
        src.rename(dest)
        _flash(request, f"✏️ Renamed to '{dest.name}'.")
    return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)


@router.post("/copy")
def copy_entry(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    target_rel: str = Form(...),
    new_name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    import shutil

    domain = _owned_domain(db, user, domain_id)
    src = _safe_join(Path(domain.docroot), target_rel)
    dest = _safe_join(src.parent, Path(new_name).name)
    if not src.exists():
        _flash(request, "❌ Item not found.")
    elif dest.exists():
        _flash(request, f"❌ '{dest.name}' already exists.")
    elif src.is_dir():
        shutil.copytree(src, dest)
        _own(domain, dest)
        _flash(request, f"📋 Copied folder to '{dest.name}'.")
    else:
        shutil.copy2(src, dest)
        _own(domain, dest)
        _flash(request, f"📋 Copied to '{dest.name}'.")
    return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)


@router.post("/extract")
def extract_archive(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    target_rel: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    import tarfile
    import zipfile

    domain = _owned_domain(db, user, domain_id)
    archive = _safe_join(Path(domain.docroot), target_rel)
    dest_dir = archive.parent
    if not archive.is_file():
        _flash(request, "❌ Archive not found.")
        return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)

    count = 0
    try:
        if archive.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive) as zf:
                for member in zf.namelist():
                    out = _safe_extract(dest_dir, member)
                    if out is None or member.endswith("/"):
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as s, open(out, "wb") as d:
                        d.write(s.read())
                    count += 1
        elif archive.name.lower().endswith((".tar", ".tar.gz", ".tgz")):
            with tarfile.open(archive) as tf:
                for member in tf.getmembers():
                    out = _safe_extract(dest_dir, member.name)
                    if out is None or not member.isfile():
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with tf.extractfile(member) as s, open(out, "wb") as d:
                        d.write(s.read())
                    count += 1
        else:
            _flash(request, "❌ Only .zip, .tar, .tar.gz archives can be extracted.")
            return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Extract failed: {exc}")
        return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)

    _own(domain, dest_dir)
    _flash(request, f"📦 Extracted {count} file(s) from '{archive.name}'.")
    return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)


def _safe_extract(base: Path, member: str) -> Path | None:
    """Resolve an archive member under base, refusing Zip-Slip escapes."""
    root = base.resolve()
    target = (root / member).resolve()
    if target == root or root in target.parents:
        return target
    return None
