# macOS peer LaunchDaemon

The setup site can install the signed, prebuilt macOS peer for Intel and Apple Silicon as a system LaunchDaemon. The daemon runs as `root` because it creates a TUN interface and manages overlay routes. The CLI bundle is not Apple-notarized; macOS may show an execution warning when it is first downloaded.

## Requirements

- macOS with Bash, Git, `curl`, Python 3, `tar`, and GitHub CLI (`gh`) with `gh attestation verify` support.
- Administrator permission to install a system LaunchDaemon and create TUN interfaces.
- An HTTPS Coordinator URL, network UUID, and a fresh one-use invite. The invite is requested at runtime and is not embedded in the generated script or LaunchDaemon plist.
- For a private Coordinator CA, install its PEM file on the Mac first and enter its absolute path in the setup form.

## Install

Use the setup site and choose **macOS · LaunchDaemon**. Download the generated script and inspect it before execution. It downloads the matching architecture archive from GitHub, verifies the checksum and Sigstore provenance, prompts for the invite with hidden input, enrolls the peer, and installs the LaunchDaemon. No Rust toolchain or target-side build is used.

The equivalent command from a checkout is:

```sh
deploy/quick-install-peer.sh --platform macos --release latest --arch auto -- \
  --network-id 00000000-0000-0000-0000-000000000000 \
  --coordinator-url https://coordinator.example:8443 \
  --invite-token-file ./invite.token \
  --instance office \
  --stun-server 111.206.174.2:3478 \
  --relay-server relay.example:42001
```

The invite file must be a regular file with mode `0600`. The setup site creates a temporary protected file from the hidden runtime prompt and removes it when installation exits. For a fixed release, replace `latest` with a published tag such as `v1.2.3`.

## Service paths and operation

- LaunchDaemon: `/Library/LaunchDaemons/net.ilovn.mini-tunnel.<instance>.plist`
- Binary: `/usr/local/libexec/mini-tunnel/<instance>/mini-tunnel`
- Private identity/state: `/var/db/mini-tunnel/<instance>` (root-only)
- Logs: `/var/log/mini-tunnel/<instance>/`

For instance `office`:

```sh
sudo launchctl print system/net.ilovn.mini-tunnel.office
sudo /usr/local/libexec/mini-tunnel/office/mini-tunnel peer status --url http://127.0.0.1:42003
sudo launchctl kickstart -k system/net.ilovn.mini-tunnel.office
```

To unload the service and remove its plist and executable while preserving the enrolled identity for reinstall/rollback:

```sh
sudo deploy/uninstall-peer-macos.sh --instance office
```

The uninstaller does not revoke membership. Revoke the device in the Coordinator first; only then remove local identity/state with:

```sh
sudo deploy/uninstall-peer-macos.sh --instance office --remove-state
```

If a membership was revoked but you want to keep the same local device identity, request a fresh one-use invite and reinstall with `--rejoin`. The installer reuses the protected local key and enrolls that device again instead of generating another identity.

If service startup fails, inspect the LaunchDaemon with `launchctl print` and read `/var/log/mini-tunnel/office/stdout.log` and `stderr.log`. After fixing the cause, rerun the generated installer with the same instance and network: it reuses state only when its recorded network ID and Coordinator match. A failed install removes its service and binary files while preserving a completed enrollment for retry. To roll back, unload the service with the uninstaller; identity/state remains available unless `--remove-state` is explicitly specified.

The installer refuses to replace an existing service or mismatched state. macOS automatic binary upgrades are not included yet. The Windows SCM installer is currently Beta and requires a Windows release containing the new service-host command; it is not Authenticode-signed. See [`deploy/windows/README.md`](../windows/README.md).
