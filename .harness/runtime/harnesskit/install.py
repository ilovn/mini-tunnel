"""Installer with owned-block merges, drift detection and versioned runtime."""
from pathlib import Path
import re
import shutil

from . import SCHEMA_VERSION, __version__
from .storage import HarnessError, apply, digest, encoded, manifest, now, read_bytes, read_json
from .templates import TOOLS, entry_block, managed_files, task_entrypoints

BEGIN = "<!-- ai-harness:begin -->"
END = "<!-- ai-harness:end -->"


def block(text):
    if BEGIN not in text and END not in text:
        return None
    if text.count(BEGIN) != 1 or text.count(END) != 1 or text.index(BEGIN) > text.index(END):
        raise HarnessError("入口标记损坏或重复，请先修复 ai-harness begin/end 标记")
    return text[text.index(BEGIN):text.index(END) + len(END)]


def block_digest(text):
    """Hash owned content canonically while preserving all surrounding bytes."""
    owned = block(text)
    if owned is None:
        return None
    normalized = owned.replace("\r\n", "\n").replace("\r", "\n")
    return digest(normalized.encode())


def _newline(text):
    if "\r\n" in text:
        return "\r\n"
    if "\r" in text:
        return "\r"
    return "\n"


def merge(text, addition):
    old = block(text)
    if old is not None:
        newline = _newline(old)
        return text.replace(old, addition.replace("\n", newline), 1)
    newline = _newline(text)
    separator = newline * 2 if text and not text.endswith((newline * 2, "\n\n", "\r\r")) else ""
    return text + separator + addition.replace("\n", newline) + newline


def release(version):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise HarnessError(f"不支持的发布版本：{version}")
    return tuple(map(int, version.split(".")))


def validate_source(source):
    if source is None:
        return None
    if not isinstance(source, dict) or set(source) != {"repository", "ref", "commit"}:
        raise HarnessError("source 必须包含 repository/ref/commit")
    if any(not isinstance(value, str) or not value.strip() for value in source.values()):
        raise HarnessError("source 字段必须是非空字符串")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source["commit"]):
        raise HarnessError("source commit 必须是完整 Git commit 哈希")
    return source


def install(root, selected, upgrade=False, dry_run=False, replace_modified=False, source=None):
    source = validate_source(source)
    root.mkdir(parents=True, exist_ok=True) if not dry_run else None
    old_bytes = read_bytes(root, ".harness/manifest.json")
    if old_bytes is not None and not upgrade:
        raise HarnessError("项目已安装；请使用 upgrade 或 status")
    if old_bytes is None and upgrade:
        raise HarnessError("项目尚未安装；请先 init")
    old = manifest(root) if old_bytes else {"files": {}, "tools": []}
    if old_bytes and release(old["kit_version"]) > release(__version__):
        raise HarnessError("拒绝降级；请使用不低于项目版本的安装器")
    tools = sorted(set(selected or old["tools"] or TOOLS) | set(old["tools"]))
    files = managed_files(tools)
    # Ship the entire small stdlib runtime, so the project works without this checkout.
    package = Path(__file__).parent
    for path in sorted(package.glob("*.py")):
        files[f".harness/runtime/harnesskit/{path.name}"] = path.read_text(encoding="utf-8")
    files[".harness/run.py"] = (
        "#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).resolve().parent / 'runtime'))\n"
        "from harnesskit.cli import main\n"
        "raise SystemExit(main(['--project', str(Path(__file__).resolve().parent.parent), *sys.argv[1:]]))\n")
    candidates = {key: value.encode() for key, value in files.items()}
    kinds = {key: "file" for key in candidates}
    entries = set()
    if "codex" in tools or "opencode" in tools:
        entries.add("AGENTS.md")
    if "claude" in tools:
        entries.add("CLAUDE.md")
    for entry in sorted(entries):
        original = read_bytes(root, entry)
        text = original.decode("utf-8") if original is not None else ""
        candidates[entry] = merge(text, entry_block()).encode()
        kinds[entry] = "block"
    conflicts = []
    records = {}
    changes = {}
    for name, data in candidates.items():
        current = read_bytes(root, name)
        kind = kinds[name]
        current_text = current.decode() if current is not None and kind == "block" else None
        actual = block_digest(current_text) if current_text is not None else (
            digest(current) if current is not None and kind != "block" else None)
        desired = block_digest(entry_block()) if kind == "block" else digest(data)
        previous = old["files"].get(name)
        if previous and actual != previous["sha256"] and actual != desired:
            conflicts.append(name)
        elif not previous and actual is not None and actual != desired:
            conflicts.append(name)
        records[name] = {"kind": kind, "sha256": desired}
        if current != data:
            changes[name] = data
    if conflicts and not replace_modified:
        raise HarnessError("本地修改/同名文件冲突（未写入）：\n" + "\n".join(conflicts) +
                           "\n人工合并后重试，或使用 --replace-modified（保留备份）")
    config = ".harness/config.json"
    if read_bytes(root, config) is None:
        changes[config] = encoded({
            "schema_version": SCHEMA_VERSION, "gates": [],
            "loop": {"max_rounds": 5, "timeout_seconds": 300, "stagnation_rounds": 2},
        })
    project = ".harness/project.md"
    if read_bytes(root, project) is None:
        changes[project] = ("# 项目上下文（项目维护，升级保留）\n\n"
                            "请填写：技术栈、目录边界、启动命令、测试命令、接口约束、交付要求。\n"
                            "存量接入先做只读调查；不要根据模板臆测项目技术栈。\n").encode()
    new = {"schema_version": SCHEMA_VERSION, "kit_version": __version__,
           "installed_at": old.get("installed_at", now()), "updated_at": old.get("updated_at", now()),
           "tools": tools, "files": records, "source": source}
    if changes or records != old.get("files") or tools != old.get("tools") or old.get("kit_version") != __version__ or source != old.get("source"):
        new["updated_at"] = now()
        changes[".harness/manifest.json"] = encoded(new)
    result = {"kit_version": __version__, "tools": tools, "source": source, "dry_run": dry_run,
              "changed": sorted(changes), "conflicts_replaced": conflicts}
    if not dry_run:
        result["backup_id"] = apply(root, changes)
    return result


def status(root):
    installed = manifest(root)
    drift = []
    for name, record in installed["files"].items():
        data = read_bytes(root, name)
        if record["kind"] == "block" and data is not None:
            actual = block_digest(data.decode())
        else:
            actual = digest(data) if data is not None else None
        if actual != record["sha256"]:
            drift.append({"path": name, "state": "missing" if data is None else "modified"})
    return {"kit_version": __version__, "project_version": installed["kit_version"],
            "schema_version": installed["schema_version"], "tools": installed["tools"],
            "source": installed.get("source"), "drift": drift}


def doctor(root):
    from .tasks import config
    result = status(root)
    cfg = config(root)
    installed = manifest(root)
    result["task_entrypoints"] = [
        {**entry, "installed": entry["path"] in installed["files"] and read_bytes(root, entry["path"]) is not None}
        for entry in task_entrypoints(installed["tools"])
    ]
    result["gates"] = [gate["name"] for gate in cfg["gates"]]
    result["warnings"] = [] if cfg["gates"] else ["尚未配置质量门禁，Loop 和 finish 会拒绝通过"]
    result["executables"] = {tool: shutil.which(tool) for tool in ("claude", "codex", "opencode")
                             if tool in result["tools"]}
    if "trae" in result["tools"]:
        result["warnings"].append("TRAE 需要在 IDE 显式加载 .harness/adapters/trae.md 中的规则")
    return result
