"""Guarded paths, atomic writes, project lock and reversible change journals."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import tempfile
import uuid

from . import SCHEMA_VERSION


class HarnessError(Exception):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(obj):
    return (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode()


def safe(root, name):
    """Reject traversal and every symlink, including an in-project symlink."""
    relative = Path(name)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise HarnessError(f"非法项目相对路径：{name}")
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise HarnessError(f"拒绝通过符号链接写入或读取：{path}")
    if path.exists() and not path.is_file() and path != root:
        raise HarnessError(f"预期文件，实际为目录：{name}")
    return path


def read_bytes(root, name):
    path = safe(root, name)
    return path.read_bytes() if path.exists() else None


def atomic(root, name, data):
    path = safe(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".harness-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(root, name):
    data = read_bytes(root, name)
    if data is None:
        raise HarnessError(f"文件不存在：{name}")
    try:
        return json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise HarnessError(f"无效 JSON：{name}: {exc}") from exc


def manifest(root):
    data = read_json(root, ".harness/manifest.json")
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError("不支持的安装清单 schema，请使用对应版本工具迁移")
    if not isinstance(data.get("kit_version"), str) or not re.fullmatch(r"\d+\.\d+\.\d+", data["kit_version"]):
        raise HarnessError("安装清单缺少有效 kit_version")
    if not isinstance(data.get("tools"), list) or any(tool not in ("claude", "codex", "opencode", "trae") for tool in data["tools"]):
        raise HarnessError("安装清单 tools 无效")
    if not isinstance(data.get("files"), dict) or not data["files"]:
        raise HarnessError("安装清单 files 无效")
    for name, record in data["files"].items():
        safe(root, name)
        if not isinstance(record, dict) or record.get("kind") not in ("block", "file") or not isinstance(record.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
            raise HarnessError(f"安装清单文件记录无效：{name}")
    return data


@contextmanager
def locked(root):
    # Validate the parent before mkdir, even on first install.
    safe(root, ".harness/.lock/owner")
    folder = root / ".harness"
    folder.mkdir(parents=True, exist_ok=True)
    lock = folder / ".lock"
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise HarnessError("项目有操作正在进行；若进程已退出，确认后删除 .harness/.lock") from exc
    try:
        (lock / "owner").write_text(f"pid={os.getpid()}\ntime={now()}\n")
        yield
    finally:
        (lock / "owner").unlink(missing_ok=True)
        lock.rmdir()


def apply(root, changes):
    """Journal before mutation; restore in-memory failures and keep an audit backup."""
    changes = {k: v for k, v in changes.items() if read_bytes(root, k) != v}
    if not changes:
        return None
    before = {k: read_bytes(root, k) for k in changes}
    backup_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
    record = {"id": backup_id, "created_at": now(), "files": {
        k: {"before": base64.b64encode(before[k]).decode() if before[k] is not None else None,
            "after_hash": digest(v) if v is not None else None}
        for k, v in changes.items()}}
    atomic(root, f".harness/backups/{backup_id}.json", encoded(record))
    try:
        for name, data in changes.items():
            if data is None:
                safe(root, name).unlink(missing_ok=True)
            else:
                atomic(root, name, data)
    except BaseException:
        for name, data in before.items():
            if data is None:
                safe(root, name).unlink(missing_ok=True)
            else:
                atomic(root, name, data)
        raise
    return backup_id
