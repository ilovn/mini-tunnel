# mini-tunnel setup site

A dependency-free static Chinese setup wizard. Run it locally with:

```sh
python3 -m http.server 4173 --directory site
```

Then open <http://127.0.0.1:4173>. `generator.mjs` validates user-entered fields and creates a Linux systemd peer bootstrap script entirely in the browser. It does not call a backend, persist form values, or collect the one-use invite. The invite is requested with hidden terminal input and held in a temporary mode-0600 file for the existing attested installer.

The generated installer supports the repository's signed Ubuntu-baseline Linux x86_64 and ARM64 artifacts. Ubuntu/Debian and compatible systemd 247+ distributions with `/dev/net/tun` are targeted. The target host needs Git, GitHub CLI with `attestation verify`, curl, Python 3, tar, and gzip. It creates/enrolls a peer only; a network and fresh invitation must already exist. Firewall changes and Coordinator deployment are outside the generated script.

The tunnel client also has macOS and Windows support, but this repository does not publish the matching official prebuilt artifacts or one-click service installers yet; the wizard labels those platforms as not available.

Run generator checks with `node site/test-generator.mjs`.
