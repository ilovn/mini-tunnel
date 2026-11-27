# Windows artifact smoke check (`fba14a8`)

Date: 2026-11-28 (China Standard Time)

Source: `fba14a8ea823630b22508147a44a8cea2c130953`

## Artifact

- Release staging run [46063426490](https://github.com/ilovn/mini-tunnel/actions/runs/46063426490) completed successfully for all Linux, macOS, and Windows architectures. The GitHub Release publish job was skipped because this was a `main` workflow dispatch.
- The Windows x86_64 ZIP passed its SHA-256 sidecar check and GitHub Sigstore attestation verification for `ilovn/mini-tunnel`, `.github/workflows/release.yml`, `refs/heads/main`, and the exact source SHA above.
- Windows x86_64 ZIP SHA-256: `193d14b1d70c119c2bfb5d69d3a392a8629faa1d455f66c2f93ad77633d4775f`.
- Extracted `mini-tunnel.exe` SHA-256: `23659dd1158ac3a7120a804b0de094fbca9dd40944d1afbb6986eb013a0e2f05`.

## VM smoke and CI

- SSH reached the existing Windows 10 x64 VMware guest at `192.168.196.130`. The guest has no Rust/Cargo installation, so it used the verified prebuilt artifact rather than compiling source.
- The copied executable's SHA-256, computed on Windows with `certutil`, matched the local extracted executable.
- `mini-tunnel.exe --version` returned `mini-tunnel 0.3.0`; `--help` listed the expected Coordinator, Relay, network, identity, and peer commands.
- The same source commit's [CI run 46063168750](https://github.com/ilovn/mini-tunnel/actions/runs/46063168750) passed all jobs, including the privileged Windows Wintun packet round-trip test.
- This smoke checks the Windows release artifact and CLI startup. It does not repeat overlay enrollment or direct/Relay network-path validation. The latest field-path reports remain [the VMware NAT follow-up](windows-current-main-vmware-nat-followup-2026-11.md) and [the current-main Relay/direct quality run](windows-current-main-relay-and-direct-quality-2026-11.md), which use source `6e25b22` and `37745e4` respectively.

## Cleanup

The temporary ZIP and executable were removed from the VM user's home directory after verification. No Windows service, adapter, route, firewall rule, or system-wide setting was changed by this smoke check.
