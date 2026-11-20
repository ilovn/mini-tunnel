# Windows peer Service Control Manager installer

The setup site can generate a Windows PowerShell installer for x64 and ARM64. It installs the prebuilt peer as a Windows Service Control Manager (SCM) service and uses the matching Wintun DLL. No Rust toolchain or compilation is needed on the target.

This installer is **Beta**. The currently published `v0.3.0` Windows archives predate the hidden `windows-service-host` command, so the generated installer will stop with an explicit message until a newer Windows release is published. The setup site labels this state and will not silently install an incompatible release. Windows binaries are not Authenticode-signed.

## Requirements

- Windows 10 or later, x64 or ARM64.
- PowerShell 5.1 or later, launched as Administrator.
- GitHub CLI (`gh`) with `gh attestation verify` support.
- Access to the GitHub API, GitHub release downloads, and `www.wintun.net` (or provide the official archive with `-WintunArchivePath`).
- An HTTPS Coordinator URL, a network UUID, and a fresh one-use invite.

## Install and operate

Choose **Windows · Service Control Manager** in the setup site. Review the generated `.ps1` file, then run it from an elevated PowerShell window. The invite is requested as a hidden secure prompt; it is not saved in the generated script, SCM command line, or service configuration. Release checksum and GitHub provenance are verified before the executable is installed. Wintun 0.14.1 is pinned by SHA-256.

The installer creates one service per instance, starts it, and waits for its loopback status endpoint. Its service recovery policy restarts after failures with bounded delays. Service logs are written to `%ProgramData%\mini-tunnel\<instance>\service.log`. At service startup, a log larger than 5 MiB is moved to `service.log.1`, replacing the previous rotated file. Program files are under `%ProgramFiles%\mini-tunnel\<instance>`; private device identity and configuration are under `%ProgramData%\mini-tunnel\<instance>` and are restricted to SYSTEM and Administrators.

For an installer named `mini-tunnel-windows-office.ps1`:

```powershell
.\mini-tunnel-windows-office.ps1 -Status
.\mini-tunnel-windows-office.ps1 -Restart
.\mini-tunnel-windows-office.ps1 -Uninstall
.\mini-tunnel-windows-office.ps1 -Uninstall -RemoveState
```

Uninstall preserves the enrolled identity by default so that reinstall and rollback keep the same device. Use `-Uninstall -RemoveState` only after revoking the device in the Coordinator; it permanently removes the local key and membership state.

## Scope and limits

- Installer and service configuration are beta until native Windows CI and live Windows SCM acceptance complete.
- The setup wizard verifies release provenance, but does not provide Authenticode signing or automatic binary upgrades.
- Status is loopback-only. Windows Firewall rules are not added automatically.
- If installation fails after successful enrollment, the identity remains on disk for a safe retry. A failed, incomplete first enrollment is removed during rollback.
