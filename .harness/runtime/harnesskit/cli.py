"""Command line interface; all project mutations take one exclusive lock."""
import argparse
import base64
import json
from pathlib import Path
import sys

from . import __version__
from .install import doctor, install, status
from .storage import HarnessError, apply, digest, encoded, locked, read_bytes, read_json
from .tasks import accept, check, collect, delegate, finish, identifier, load_task, loop, new_task
from .templates import ROLES, TOOLS, WORKFLOWS


def parser():
    result = argparse.ArgumentParser(prog="ai-harness", description="多工具工程 Harness、任务与有界 Loop")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--project", default=".", help="目标项目目录，默认为当前目录")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("init", "upgrade"):
        command = commands.add_parser(name, help="安装项目能力" if name == "init" else "安全升级项目能力")
        command.add_argument("--tools", nargs="+", choices=TOOLS, help="默认全部；升级时保留已安装工具")
        command.add_argument("--dry-run", action="store_true")
        command.add_argument("--source", type=json.loads, help="安装脚本提供的 Git 来源 JSON（repository/ref/commit）")
        command.add_argument("--replace-modified", action="store_true", help="显式覆盖冲突的受管内容，先备份")
    commands.add_parser("status", help="查看 CLI/项目版本及受管文件变更")
    commands.add_parser("doctor", help="检查配置、门禁与工具可用性")
    scan = commands.add_parser("scan", help="批量识别多个项目应用的版本")
    scan.add_argument("paths", nargs="+", help="明确指定的项目根目录")
    restore = commands.add_parser("restore", help="恢复一次安装/升级备份；有后续修改则拒绝")
    restore.add_argument("backup_id")
    task = commands.add_parser("task", help="创建、分派、续接与验收任务")
    subs = task.add_subparsers(dest="task_command", required=True)
    new = subs.add_parser("new")
    new.add_argument("kind", choices=WORKFLOWS)
    new.add_argument("title")
    new.add_argument("--id")
    new.add_argument("--accept", action="append", default=[], help="可重复的验收标准")
    subs.add_parser("list")
    show = subs.add_parser("show")
    show.add_argument("id")
    assignment = subs.add_parser("delegate")
    assignment.add_argument("id")
    assignment.add_argument("role", choices=ROLES)
    assignment.add_argument("title")
    assignment.add_argument("--scope", required=True)
    assignment.add_argument("--depends-on", action="append", default=[])
    collection = subs.add_parser("collect")
    collection.add_argument("id")
    collection.add_argument("child_id")
    acceptance = subs.add_parser("accept")
    acceptance.add_argument("id")
    acceptance.add_argument("criteria", nargs="+")
    complete = subs.add_parser("finish", help="调用方确认业务验收与交付物后执行")
    complete.add_argument("id")
    complete.add_argument("--summary", required=True)
    verification = commands.add_parser("check", help="执行配置的质量门禁")
    verification.add_argument("id")
    runner = commands.add_parser("loop", help="受限 worker → 验证 → 反馈循环")
    runner.add_argument("id")
    runner.add_argument("--worker", required=True, help='JSON argv；通过 stdin 传入提示词，也支持 {prompt} 文件占位符')
    runner.add_argument("--rounds", type=int)
    runner.add_argument("--timeout", type=int, help="每轮 worker 超时秒数；gate 使用自身超时")
    return result


def restore(root, backup_id):
    identifier(backup_id)
    backup = read_json(root, f".harness/backups/{backup_id}.json")
    changes = {}
    for name, record in backup["files"].items():
        data = read_bytes(root, name)
        before = base64.b64decode(record["before"], validate=True) if record["before"] is not None else None
        actual = digest(data) if data is not None else None
        before_hash = digest(before) if before is not None else None
        if actual not in (record["after_hash"], before_hash):
            raise HarnessError(f"备份后文件有变化，拒绝覆盖：{name}")
        changes[name] = before
    return {"restored": backup_id, "undo_backup_id": apply(root, changes)}


def execute(args, root):
    if args.command in ("init", "upgrade"):
        return install(root, args.tools, args.command == "upgrade", args.dry_run, args.replace_modified, args.source)
    if args.command == "restore":
        return restore(root, args.backup_id)
    if args.command == "status":
        return status(root)
    if args.command == "doctor":
        return doctor(root)
    if args.command == "scan":
        results = []
        for path in args.paths:
            project = Path(path).expanduser().resolve()
            try:
                results.append({"project": str(project), **status(project)})
            except (HarnessError, OSError) as exc:
                results.append({"project": str(project), "error": str(exc)})
        return results
    if args.command == "check":
        return check(root, args.id)
    if args.command == "loop":
        try:
            worker = json.loads(args.worker)
        except ValueError as exc:
            raise HarnessError("--worker 需要合法的 JSON argv 数组") from exc
        return loop(root, args.id, worker, args.rounds, args.timeout)
    if args.task_command == "new":
        if not args.title.strip() or any(not a.strip() for a in args.accept):
            raise HarnessError("标题或验收标准不能为空")
        return new_task(root, args.kind, args.title, args.id, args.accept)
    if args.task_command == "show":
        return load_task(root, args.id)
    if args.task_command == "list":
        from .storage import manifest, safe
        manifest(root)
        safe(root, ".harness/tasks/.probe")
        return [load_task(root, path.parent.name) for path in sorted((root / ".harness/tasks").glob("*/task.json"))]
    if args.task_command == "delegate":
        return delegate(root, args.id, args.role, args.title, args.scope, args.depends_on)
    if args.task_command == "collect":
        return collect(root, args.id, args.child_id)
    if args.task_command == "accept":
        return accept(root, args.id, args.criteria)
    if args.task_command == "finish":
        return finish(root, args.id, args.summary)
    raise HarnessError("未知命令")


def main(argv=None):
    args = parser().parse_args(argv)
    root = Path(args.project).expanduser().resolve()
    read_only = args.command in ("status", "doctor", "scan") or (
        args.command in ("init", "upgrade") and args.dry_run) or (
        args.command == "task" and args.task_command in ("show", "list"))
    try:
        if read_only:
            output = execute(args, root)
        else:
            with locked(root):
                output = execute(args, root)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        if args.command in ("status", "doctor") and output["drift"]:
            return 1
        if args.command == "check" and not output["passed"]:
            return 1
        if args.command == "loop" and output["reason"] != "checks_passed":
            return 1
        if args.command == "scan" and any("error" in item or item.get("drift") for item in output):
            return 1
        return 0
    except (HarnessError, OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        print(f"ai-harness: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ai-harness: 已中断；已完成的轮次及日志保留，可重新运行", file=sys.stderr)
        return 130
