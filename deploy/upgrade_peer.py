#!/usr/bin/env python3
"""Atomically upgrade one installed systemd peer and roll back on failed health checks."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence


class UpgradeError(RuntimeError):
    pass


class UpgradeInterrupted(UpgradeError):
    pass


@dataclass(frozen=True)
class UpgradeConfig:
    instance: str
    binary: Path
    binary_path: Path = Path("/usr/local/bin/mini-tunnel")
    config_dir: Path = Path("/etc/mini-tunnel")
    backup_dir: Path = Path("/usr/local/lib/mini-tunnel/backups")
    staging_dir: Path = Path("/usr/local/lib/mini-tunnel/upgrade-staging")
    lock_dir: Path = Path("/run/lock")
    health_timeout_seconds: float = 30.0
    poll_interval_seconds: float = 1.0
    require_root_ownership: bool = True

    @property
    def service(self) -> str:
        return f"mini-tunnel-peer@{self.instance}.service"

    @property
    def service_config(self) -> Path:
        return self.config_dir / f"peer-{self.instance}.env"


Runner = Callable[..., subprocess.CompletedProcess]


def _run(command: Sequence[str], *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _checked(
    runner: Runner, command: Sequence[str], *, timeout: float = 15.0
) -> subprocess.CompletedProcess[str]:
    result = runner(command, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise UpgradeError(f"command failed ({result.returncode}): {command[0]} {detail}")
    return result


def _read_status_url(path: Path) -> str:
    value: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\s*MINI_TUNNEL_STATUS_LISTEN=([^\s#]+)\s*", raw_line)
        if match:
            value = match.group(1).strip("\"'")
    if value is None:
        value = "127.0.0.1:42003"
    match = re.fullmatch(r"(?:127\.0\.0\.1|\[::1\]):([0-9]{1,5})", value)
    if match and 1 <= int(match.group(1)) <= 65535:
        return f"http://{value}"
    raise UpgradeError("peer status listener must be a loopback host and port")


def _preflight(config: UpgradeConfig, runner: Runner) -> tuple[str, os.stat_result]:
    _validate_instance(config.instance)
    if not 0 < config.health_timeout_seconds <= 300 or config.poll_interval_seconds <= 0:
        raise UpgradeError("health timeout must be between 0 and 300 seconds")
    source = config.binary
    if source.is_symlink() or not source.is_file() or not os.access(source, os.X_OK):
        raise UpgradeError("candidate binary must be an executable regular file, not a symlink")
    target = config.binary_path
    if target.is_symlink() or not target.is_file():
        raise UpgradeError("installed peer binary must be an existing regular file, not a symlink")
    if source.resolve(strict=True) == target.resolve(strict=True):
        raise UpgradeError("candidate binary is already the installed target")
    parent_stat = os.stat(target.parent, follow_symlinks=False)
    if (config.require_root_ownership and parent_stat.st_uid != 0) or parent_stat.st_mode & 0o022:
        raise UpgradeError("installed peer binary directory must be root-owned and not group/world-writable")
    target_stat = os.stat(target, follow_symlinks=False)
    if (config.require_root_ownership and target_stat.st_uid != 0) or target_stat.st_mode & 0o022:
        raise UpgradeError("installed peer binary must be root-owned and not group/world-writable")
    service_config = config.service_config
    if service_config.is_symlink() or not service_config.is_file():
        raise UpgradeError(f"peer instance is not installed: missing {service_config}")
    config_dir_stat = os.stat(config.config_dir, follow_symlinks=False)
    if (config.require_root_ownership and config_dir_stat.st_uid != 0) or config_dir_stat.st_mode & 0o022:
        raise UpgradeError("peer config directory must be root-owned and not group/world-writable")
    config_stat = os.stat(service_config, follow_symlinks=False)
    if (config.require_root_ownership and config_stat.st_uid != 0) or config_stat.st_mode & 0o022:
        raise UpgradeError("peer instance config must be root-owned and not group/world-writable")
    _read_status_url(service_config)
    _checked(runner, ["systemctl", "is-active", "--quiet", config.service])
    _checked(runner, ["runuser", "-u", "mini-tunnel", "--", str(source), "--help"])
    return _read_status_url(service_config), target_stat


def _validate_instance(instance: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", instance):
        raise UpgradeError("invalid instance name")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_fsynced(source: Path, destination: Path, mode: int, uid: int, gid: int) -> None:
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        shutil.copyfileobj(input_file, output_file)
        output_file.flush()
        os.fsync(output_file.fileno())
    os.chmod(destination, stat.S_IMODE(mode))
    os.chown(destination, uid, gid)


def _atomic_install(source: Path, target: Path, original: os.stat_result) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.upgrade-", dir=target.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    try:
        _copy_fsynced(source, temporary, original.st_mode, original.st_uid, original.st_gid)
        os.replace(temporary, target)
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _wait_healthy(
    config: UpgradeConfig,
    status_url: str,
    runner: Runner,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    deadline = monotonic() + config.health_timeout_seconds
    last_error = "service has not become healthy"
    while monotonic() < deadline:
        active = runner(["systemctl", "is-active", "--quiet", config.service], timeout=5.0)
        if active.returncode == 0:
            try:
                result = _checked(
                    runner,
                    [
                        "runuser",
                        "-u",
                        "mini-tunnel",
                        "--",
                        str(config.binary_path),
                        "peer",
                        "status",
                        "--url",
                        status_url,
                    ],
                    timeout=4.0,
                )
                status = json.loads(result.stdout)
                if isinstance(status, list) and all(isinstance(peer, dict) for peer in status):
                    return
                last_error = "peer status endpoint returned an unexpected JSON shape"
            except (UpgradeError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
                last_error = str(error)
        sleep(config.poll_interval_seconds)
    raise UpgradeError(f"peer service health check timed out: {last_error}")


def _backup_current(config: UpgradeConfig, original: os.stat_result) -> tuple[Path, Path]:
    backup_dir = config.backup_dir / config.instance
    if backup_dir.is_symlink():
        raise UpgradeError(f"refusing symlink backup directory: {backup_dir}")
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup_stat = os.stat(backup_dir, follow_symlinks=False)
    if (config.require_root_ownership and backup_stat.st_uid != 0) or backup_stat.st_mode & 0o077:
        raise UpgradeError(f"backup directory must be root-owned and private: {backup_dir}")
    os.chmod(backup_dir, 0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = backup_dir / f"mini-tunnel-{timestamp}-{_sha256(config.binary_path)[:12]}"
    _copy_fsynced(config.binary_path, backup, original.st_mode, original.st_uid, original.st_gid)
    candidate_backup = backup_dir / f"candidate-{timestamp}-{_sha256(config.binary)[:12]}"
    _copy_fsynced(config.binary, candidate_backup, original.st_mode, original.st_uid, original.st_gid)
    directory_fd = os.open(backup_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return backup, candidate_backup


def _stage_candidate(config: UpgradeConfig) -> Path:
    source = config.binary
    if source.is_symlink() or not source.is_file() or not os.access(source, os.X_OK):
        raise UpgradeError("candidate binary must be an executable regular file, not a symlink")
    if config.staging_dir.is_symlink():
        raise UpgradeError("candidate staging directory must not be a symlink")
    config.staging_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    staging_stat = os.stat(config.staging_dir, follow_symlinks=False)
    if (config.require_root_ownership and staging_stat.st_uid != 0) or staging_stat.st_mode & 0o022:
        raise UpgradeError("candidate staging directory must be root-owned and not group/world-writable")
    os.chmod(config.staging_dir, 0o755)
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    source_stat = os.fstat(source_fd)
    if not stat.S_ISREG(source_stat.st_mode) or not source_stat.st_mode & 0o111:
        os.close(source_fd)
        raise UpgradeError("candidate binary changed or is not an executable regular file")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".mini-tunnel-{config.instance}-", dir=config.staging_dir
    )
    candidate = Path(temporary_name)
    try:
        with os.fdopen(source_fd, "rb") as input_file, os.fdopen(descriptor, "wb") as output_file:
            shutil.copyfileobj(input_file, output_file)
            output_file.flush()
            os.fchown(
                output_file.fileno(),
                0 if config.require_root_ownership else os.getuid(),
                0 if config.require_root_ownership else os.getgid(),
            )
            os.fchmod(output_file.fileno(), 0o755)
            os.fsync(output_file.fileno())
        directory_fd = os.open(config.staging_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return candidate
    except BaseException:
        candidate.unlink(missing_ok=True)
        raise


def upgrade(
    config: UpgradeConfig,
    runner: Runner = _run,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Path:
    _validate_instance(config.instance)
    if not 0 < config.health_timeout_seconds <= 300 or config.poll_interval_seconds <= 0:
        raise UpgradeError("health timeout must be between 0 and 300 seconds")
    if config.lock_dir.is_symlink():
        raise UpgradeError("upgrade lock directory must not be a symlink")
    config.lock_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    lock_dir_stat = os.stat(config.lock_dir, follow_symlinks=False)
    if (config.require_root_ownership and lock_dir_stat.st_uid != 0) or lock_dir_stat.st_mode & 0o022:
        raise UpgradeError("upgrade lock directory must be root-owned and not group/world-writable")
    lock_path = config.lock_dir / f"mini-tunnel-upgrade-{config.instance}.lock"
    descriptor = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_stat = os.fstat(descriptor)
        if config.require_root_ownership and lock_stat.st_uid != 0:
            raise UpgradeError("upgrade lock must be root-owned")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise UpgradeError(f"another upgrade is running for instance {config.instance}") from error
        candidate = _stage_candidate(config)
        staged_config = UpgradeConfig(
            instance=config.instance,
            binary=candidate,
            binary_path=config.binary_path,
            config_dir=config.config_dir,
            backup_dir=config.backup_dir,
            staging_dir=config.staging_dir,
            lock_dir=config.lock_dir,
            health_timeout_seconds=config.health_timeout_seconds,
            poll_interval_seconds=config.poll_interval_seconds,
            require_root_ownership=config.require_root_ownership,
        )
        try:
            return _upgrade_locked(staged_config, runner, monotonic=monotonic, sleep=sleep)
        finally:
            candidate.unlink(missing_ok=True)
    finally:
        os.close(descriptor)


def _upgrade_locked(
    config: UpgradeConfig,
    runner: Runner,
    *,
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
) -> Path:
    status_url, original = _preflight(config, runner)
    backup, candidate_backup = _backup_current(config, original)
    original_digest = _sha256(config.binary_path)
    old_handlers: dict[int, object] = {}

    def interrupted(signum: int, _frame: object) -> None:
        raise UpgradeInterrupted(f"received signal {signum}")

    for signum in (signal.SIGINT, signal.SIGTERM):
        old_handlers[signum] = signal.signal(signum, interrupted)
    replaced = False
    try:
        _atomic_install(config.binary, config.binary_path, original)
        replaced = True
        _checked(runner, ["systemctl", "restart", config.service], timeout=60.0)
        _wait_healthy(config, status_url, runner, monotonic=monotonic, sleep=sleep)
        candidate_backup.unlink(missing_ok=True)
        return backup
    except BaseException as error:
        if not replaced:
            try:
                replaced = _sha256(config.binary_path) != original_digest
            except OSError:
                replaced = True
            if not replaced:
                candidate_backup.unlink(missing_ok=True)
                raise
        try:
            _atomic_install(backup, config.binary_path, original)
            _checked(runner, ["systemctl", "restart", config.service], timeout=60.0)
            _wait_healthy(config, status_url, runner, monotonic=monotonic, sleep=sleep)
            candidate_backup.unlink(missing_ok=True)
        except BaseException as rollback_error:
            raise UpgradeError(
                f"upgrade failed ({error}); automatic rollback also failed ({rollback_error}); "
                f"old binary backup retained at {backup}, candidate retained at {candidate_backup}, "
                f"and active file at {config.binary_path} must be inspected"
            ) from error
        raise UpgradeError(f"upgrade failed and was rolled back to the previous binary ({backup}): {error}") from error
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="prebuilt candidate already verified by deploy/download-peer.sh")
    parser.add_argument("--instance", required=True, help="existing systemd peer instance name")
    parser.add_argument("--health-timeout", type=float, default=30.0, help="seconds to wait for loopback status (default: 30)")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if os.geteuid() != 0:
        print("error: run as root, for example with sudo", file=sys.stderr)
        return 2
    config = UpgradeConfig(
        instance=args.instance,
        binary=args.binary,
        health_timeout_seconds=args.health_timeout,
    )
    try:
        backup = upgrade(config)
    except (UpgradeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"upgrade successful; previous binary retained at {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
