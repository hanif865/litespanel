"""File manager — browse/upload/edit/delete within a domain's docroot.

Every path is resolved and checked to stay inside the selected domain's
document root, so a crafted "../.." can never escape the sandbox.
"""
from __future__ import annotations

import shutil
from datetime import datetime
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
    hidden: int = 0,
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

    in_trash = path.split("/")[0] == ".trash"
    entries = []
    for child in sorted(current.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
        if child.name == ".trash" and not path:
            continue  # hide the trash folder from the normal root view
        if child.name.startswith(".") and not hidden:
            continue  # dotfiles hidden unless "Show Hidden" is on
        stat = child.stat()
        rel = child.relative_to(docroot.resolve()).as_posix()
        is_dir = child.is_dir()
        entries.append({
            "name": child.name,
            "rel": rel,
            "is_dir": is_dir,
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            "perms": oct(stat.st_mode)[-4:],
            "icon": _file_icon(child.name, is_dir),
            "kind": "Folder" if is_dir else _file_kind(child.name),
            "is_html": (not is_dir) and child.suffix.lower() in (".html", ".htm"),
            "is_archive": (not is_dir) and child.name.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz")),
            "editable": child.is_file()
            and stat.st_size <= MAX_EDIT_BYTES
            and (child.suffix.lower() in TEXT_SUFFIXES or child.name in TEXT_SUFFIXES),
        })

    parent = None
    if path:
        parent = str(Path(path).parent.as_posix())
        parent = "" if parent == "." else parent

    # Breadcrumb segments for the current path.
    crumbs, acc = [], ""
    for seg in [s for s in path.split("/") if s]:
        acc = f"{acc}/{seg}" if acc else seg
        crumbs.append({"name": seg, "path": acc})

    ctx.update({
        "selected": domain, "entries": entries, "path": path, "parent": parent,
        "crumbs": crumbs, "tree": _folder_tree(docroot), "in_trash": in_trash,
        "show_hidden": bool(hidden),
    })
    return templates.TemplateResponse(request, "files.html", ctx)


def _file_kind(name: str) -> str:
    suffix = Path(name).suffix.lower().lstrip(".")
    return f"{suffix.upper()} File" if suffix else "File"


# Emoji icon per file extension (cPanel-style type icons).
_FILE_ICONS = {
    "html": "🌐", "htm": "🌐", "css": "🎨", "js": "📜", "php": "🐘", "py": "🐍",
    "json": "🧩", "xml": "📋", "yml": "📋", "yaml": "📋", "md": "📝", "txt": "📄",
    "env": "⚙️", "ini": "⚙️", "conf": "⚙️", "htaccess": "⚙️", "sh": "⚡", "log": "🧾",
    "zip": "📦", "tar": "📦", "gz": "📦", "tgz": "📦", "rar": "📦", "7z": "📦",
    "png": "🖼️", "jpg": "🖼️", "jpeg": "🖼️", "gif": "🖼️", "svg": "🖼️", "webp": "🖼️", "ico": "🖼️",
    "pdf": "📕", "doc": "📘", "docx": "📘", "xls": "📗", "xlsx": "📗", "ppt": "📙", "pptx": "📙",
    "mp4": "🎬", "mov": "🎬", "webm": "🎬", "avi": "🎬", "mp3": "🎵", "wav": "🎵",
    "sql": "🗄️", "db": "🗄️", "sqlite": "🗄️",
}


def _file_icon(name: str, is_dir: bool) -> str:
    if is_dir:
        return "📁"
    return _FILE_ICONS.get(Path(name).suffix.lower().lstrip("."), "📄")


def _folder_tree(docroot: Path, max_entries: int = 300) -> list[dict]:
    """A flat, depth-tagged list of folders under docroot for the left tree."""
    root = docroot.resolve()
    items, count = [], 0
    for p in sorted(root.rglob("*")):
        if count >= max_entries:
            break
        try:
            if p.is_dir() and not any(part.startswith(".trash") for part in p.parts):
                rel = p.relative_to(root)
                items.append({"name": p.name, "rel": rel.as_posix(), "depth": len(rel.parts)})
                count += 1
        except (OSError, ValueError):
            continue
    return items


@router.get("/upload")
def upload_page(
    request: Request,
    domain_id: int,
    path: str = "",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    return templates.TemplateResponse(
        request, "upload.html",
        {"user": user, "domain": domain, "path": path, "active": "files"},
    )


@router.post("/upload")
async def upload(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    file: UploadFile = File(...),
    overwrite: str = Form("0"),
    ajax: str = Form("0"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    from fastapi.responses import JSONResponse

    domain = _owned_domain(db, user, domain_id)
    dest_dir = _safe_join(Path(domain.docroot), path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    filename = Path(file.filename or "upload.bin").name  # strip any path parts
    dest = _safe_join(dest_dir, filename)

    if dest.exists() and overwrite != "1":
        msg = f"'{filename}' already exists — enable Overwrite to replace it."
        if ajax == "1":
            return JSONResponse({"ok": False, "name": filename, "error": msg}, status_code=409)
        _flash(request, f"❌ {msg}")
        return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)

    with dest.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            out.write(chunk)
    _own(domain, dest)
    if ajax == "1":
        return JSONResponse({"ok": True, "name": filename, "size": dest.stat().st_size})
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


@router.get("/htmledit")
def html_editor(
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
        "htmledit.html",
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


TRASH = ".trash"


def _redir(domain_id: int, path: str) -> RedirectResponse:
    return RedirectResponse(f"/files?domain_id={domain_id}&path={path}", status_code=303)


def _resolve_targets(docroot: Path, rels: list[str]) -> list[Path]:
    """Resolve a list of relative paths under docroot, dropping the root itself."""
    root = docroot.resolve()
    items = []
    for rel in rels:
        if not rel:
            continue
        t = _safe_join(docroot, rel)
        if t != root:
            items.append(t)
    return items


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
        return _redir(domain_id, path)
    target = _safe_join(_safe_join(Path(domain.docroot), path), filename)
    if target.exists():
        _flash(request, f"❌ '{filename}' already exists.")
    else:
        target.touch()
        _own(domain, target)
        _flash(request, f"📄 File '{filename}' created.")
    return _redir(domain_id, path)


@router.post("/trash")
def trash(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    docroot = Path(domain.docroot)
    trash_dir = _safe_join(docroot, TRASH)
    trash_dir.mkdir(exist_ok=True)
    n = 0
    for t in _resolve_targets(docroot, targets):
        if TRASH in t.relative_to(docroot.resolve()).parts:
            continue
        dest = trash_dir / t.name
        i = 1
        while dest.exists():
            dest, i = trash_dir / f"{t.name}.{i}", i + 1
        shutil.move(str(t), str(dest))
        n += 1
    _flash(request, f"🗑️ Moved {n} item(s) to Trash." if n else "❌ Nothing selected.")
    return _redir(domain_id, path)


@router.post("/restore")
def restore(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    docroot = Path(domain.docroot)
    n = 0
    for t in _resolve_targets(docroot, targets):
        dest = _safe_join(docroot, t.name)
        if not dest.exists():
            shutil.move(str(t), str(dest))
            _own(domain, dest)
            n += 1
    _flash(request, f"♻️ Restored {n} item(s) from Trash.")
    return _redir(domain_id, path)


@router.post("/emptytrash")
def empty_trash(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    trash_dir = _safe_join(Path(domain.docroot), TRASH)
    if trash_dir.is_dir():
        shutil.rmtree(trash_dir, ignore_errors=True)
    _flash(request, "🧹 Trash emptied.")
    return _redir(domain_id, path)


@router.post("/delete")
def delete_permanent(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    n = 0
    for t in _resolve_targets(Path(domain.docroot), targets):
        if t.is_dir():
            shutil.rmtree(t, ignore_errors=True)
        elif t.exists():
            t.unlink()
        n += 1
    _flash(request, f"❌ Permanently deleted {n} item(s).")
    return _redir(domain_id, path)


@router.post("/rename")
def rename_entry(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    new_name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    items = _resolve_targets(Path(domain.docroot), targets)
    if len(items) != 1:
        _flash(request, "❌ Select exactly one item to rename.")
        return _redir(domain_id, path)
    src = items[0]
    dest = _safe_join(src.parent, Path(new_name).name)
    if dest.exists():
        _flash(request, f"❌ '{dest.name}' already exists.")
    else:
        src.rename(dest)
        _flash(request, f"✏️ Renamed to '{dest.name}'.")
    return _redir(domain_id, path)


@router.post("/copy")
def copy_entries(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    dest: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    docroot = Path(domain.docroot)
    dest_dir = _safe_join(docroot, dest.strip().lstrip("/"))
    if not dest_dir.is_dir():
        _flash(request, "❌ Destination folder not found.")
        return _redir(domain_id, path)
    n = 0
    for src in _resolve_targets(docroot, targets):
        out = dest_dir / src.name
        if out == src or out.exists():
            continue
        if src.is_dir():
            shutil.copytree(src, out)
        else:
            shutil.copy2(src, out)
        _own(domain, out)
        n += 1
    _flash(request, f"📋 Copied {n} item(s) into '{dest or 'public_html'}'.")
    return _redir(domain_id, path)


@router.post("/move")
def move_entries(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    dest: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    docroot = Path(domain.docroot)
    dest_dir = _safe_join(docroot, dest.strip().lstrip("/"))
    if not dest_dir.is_dir():
        _flash(request, "❌ Destination folder not found.")
        return _redir(domain_id, path)
    n = 0
    for t in _resolve_targets(docroot, targets):
        target = dest_dir / t.name
        if target != t and not target.exists():
            shutil.move(str(t), str(target))
            _own(domain, target)
            n += 1
    _flash(request, f"➡️ Moved {n} item(s) to '{dest}'.")
    return _redir(domain_id, path)


@router.post("/chmod")
def chmod_entries(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    perms: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _owned_domain(db, user, domain_id)
    perms = perms.strip()
    if not (perms.isdigit() and len(perms) in (3, 4) and all(c in "01234567" for c in perms)):
        _flash(request, "❌ Permissions must be octal, e.g. 755 or 0644.")
        return _redir(domain_id, path)
    mode = int(perms, 8)
    n = 0
    for t in _resolve_targets(Path(domain.docroot), targets):
        try:
            t.chmod(mode)
            n += 1
        except OSError:
            pass
    _flash(request, f"🔧 Set permissions {perms} on {n} item(s).")
    return _redir(domain_id, path)


@router.post("/compress")
def compress_entries(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    archive_name: str = Form("archive.zip"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    import zipfile

    domain = _owned_domain(db, user, domain_id)
    docroot = Path(domain.docroot)
    items = _resolve_targets(docroot, targets)
    if not items:
        _flash(request, "❌ Nothing selected to compress.")
        return _redir(domain_id, path)
    name = Path(archive_name).name or "archive.zip"
    if not name.lower().endswith(".zip"):
        name += ".zip"
    dest = _safe_join(_safe_join(docroot, path), name)
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for t in items:
            if t.is_dir():
                for f in t.rglob("*"):
                    if f.is_file():
                        zf.write(f, f"{t.name}/{f.relative_to(t).as_posix()}")
            elif t.is_file():
                zf.write(t, t.name)
    _own(domain, dest)
    _flash(request, f"🗜️ Created '{name}' from {len(items)} item(s).")
    return _redir(domain_id, path)


@router.post("/extract")
def extract_archive(
    request: Request,
    domain_id: int = Form(...),
    path: str = Form(""),
    targets: list[str] = Form(default=[]),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    import tarfile
    import zipfile

    domain = _owned_domain(db, user, domain_id)
    items = _resolve_targets(Path(domain.docroot), targets)
    if len(items) != 1 or not items[0].is_file():
        _flash(request, "❌ Select one archive file to extract.")
        return _redir(domain_id, path)
    archive = items[0]
    dest_dir = archive.parent
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
            _flash(request, "❌ Only .zip, .tar, .tar.gz can be extracted.")
            return _redir(domain_id, path)
    except Exception as exc:  # noqa: BLE001
        _flash(request, f"❌ Extract failed: {exc}")
        return _redir(domain_id, path)
    _own(domain, dest_dir)
    _flash(request, f"📦 Extracted {count} file(s) from '{archive.name}'.")
    return _redir(domain_id, path)


def _safe_extract(base: Path, member: str) -> Path | None:
    """Resolve an archive member under base, refusing Zip-Slip escapes."""
    root = base.resolve()
    target = (root / member).resolve()
    if target == root or root in target.parents:
        return target
    return None
