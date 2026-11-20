# mini-tunnel setup site

A dependency-free static Chinese setup wizard. Run it locally with:

```sh
python3 -m http.server 4173 --directory site
```

Then open <http://127.0.0.1:4173>. `generator.mjs` validates user-entered fields and creates Linux systemd or macOS LaunchDaemon peer setup scripts entirely in the browser. It does not call a backend, persist form values, or collect the one-use invite. The invite is requested with hidden terminal input and held in a temporary mode-0600 file for the attested installer.

The generated installer supports the repository's signed Ubuntu-baseline Linux x86_64/ARM64 releases and attested macOS Intel/Apple Silicon releases. Linux targets are Ubuntu/Debian or compatible systemd 247+ distributions with `/dev/net/tun`; macOS installs a root LaunchDaemon so TUN and route management work after boot. Both targets need Git, GitHub CLI with `attestation verify`, curl, Python 3, tar, and gzip. It creates/enrolls a peer only; a network and fresh invitation must already exist. Firewall changes and Coordinator deployment are outside the generated script.

For hosts that cannot reach GitHub directly, open **高级选项** and set a GitHub mirror prefix such as `https://ghproxy.net/https://github.com/`. The mirror must support Git cloning and release asset downloads; GitHub API requests still go directly to `api.github.com`. The downloaded release remains protected by its published digest and Sigstore attestation. The script checks that `gh attestation verify` is available before prompting for an invite.

Use **生成 UUID** when creating a new network. The adjacent **创建新网络** panel builds a CLI command that sends this same ID to a Coordinator running the new `--network-id` API. Both the CLI and Coordinator must support the flag. Run that command, then create a one-use invite with the returned admin token. The same ID remains in the peer deployment form. Existing Coordinator networks should keep using their assigned ID.

The macOS service installer is documented in [`../deploy/macos/README.md`](../deploy/macos/README.md). macOS binaries are not Apple-notarized. Windows x64/ARM64 remains a CLI-only archive with no service installer or generated one-click tunnel setup; the site keeps that limitation visible.

Run generator checks with `node site/test-generator.mjs`.
