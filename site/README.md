# mini-tunnel setup site

A dependency-free static Chinese setup wizard. Run it locally with:

```sh
python3 -m http.server 4173 --directory site
```

Then open <http://127.0.0.1:4173>. `generator.mjs` validates user-entered fields and creates a Linux systemd peer bootstrap script entirely in the browser. It does not call a backend, persist form values, or collect the one-use invite. The invite is requested with hidden terminal input and held in a temporary mode-0600 file for the existing attested installer.

The generated installer supports the repository's signed Ubuntu-baseline Linux x86_64 and ARM64 artifacts. Ubuntu/Debian and compatible systemd 247+ distributions with `/dev/net/tun` are targeted. The target host needs Git, GitHub CLI with `attestation verify`, curl, Python 3, tar, and gzip. It creates/enrolls a peer only; a network and fresh invitation must already exist. Firewall changes and Coordinator deployment are outside the generated script.

For hosts that cannot reach GitHub directly, open **高级选项** and set a GitHub mirror prefix such as `https://ghproxy.net/https://github.com/`. The mirror must support Git cloning and release asset downloads; GitHub API requests still go directly to `api.github.com`. The downloaded release remains protected by its published digest and Sigstore attestation. The script checks that `gh attestation verify` is available before prompting for an invite.

Use **生成 UUID** when creating a new network. The adjacent **创建新网络** panel builds a CLI command that sends this same ID to a Coordinator running the new `--network-id` API. Both the CLI and Coordinator must support the flag. Run that command, then create a one-use invite with the returned admin token. The same ID remains in the peer deployment form. Existing Coordinator networks should keep using their assigned ID.

Release v0.3.0 publishes command-line archives for macOS Intel/Apple Silicon and Windows x64/ARM64. They are not code-signed or notarized and do not include platform-specific service installers or a one-click tunnel setup flow. The website links the downloads and continues to generate one-click systemd deployment only for Linux.

Run generator checks with `node site/test-generator.mjs`.
