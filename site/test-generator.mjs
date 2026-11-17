import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  generateNetworkCreateCommand,
  generateNetworkId,
  generateScript,
  validateConfig,
  validateNetworkSetup,
} from "./generator.mjs";

const base = {
  coordinatorUrl: "https://coord.example.net:8443",
  coordinatorMode: "existing",
  networkId: "81af0d3b-be18-4b8f-976e-2b2a37ddfbc9",
  instance: "office",
  arch: "x86_64",
  versionMode: "latest",
  release: "",
  stunServer: "111.206.174.2:3478",
  relayServer: "relay.example.net:42001",
  udpRelayServer: "",
  coordinatorCa: "",
  githubMirrorPrefix: "",
};
assert.deepEqual(validateConfig(base), {});
assert.match(generateScript(base), /'--arch'[\s\\]+\s+'x86_64'/);
assert.match(generateScript(base), /read -r -s/);
assert.match(
  generateScript(base),
  /'--invite-token-file'[\s\\]+\s+"\$invite_file"/,
);
assert.doesNotMatch(generateScript(base), /test-invite-secret/);
assert.match(generateScript(base), /gh attestation verify --help/);
assert.equal(
  spawnSync("bash", ["-n"], { input: generateScript(base), encoding: "utf8" })
    .status,
  0,
);
assert.match(
  generateScript({ ...base, coordinatorMode: "custom" }),
  /Source: custom Coordinator/,
);
assert.match(
  generateScript({ ...base, versionMode: "release", release: "v1.2.3" }),
  /'v1\.2\.3'/,
);
const mirrored = {
  ...base,
  githubMirrorPrefix: "https://ghproxy.net/https://github.com/",
};
assert.deepEqual(validateConfig(mirrored), {});
assert.match(generateScript(mirrored), /MINI_TUNNEL_GITHUB_MIRROR_PREFIX/);
assert.match(generateScript(mirrored), /\$\{github_mirror_prefix\}ilovn\/mini-tunnel\.git/);
assert.match(generateScript(mirrored), /'https:\/\/ghproxy\.net\/https:\/\/github\.com\/'/);
assert.equal(
  spawnSync("bash", ["-n"], {
    input: generateScript(mirrored),
    encoding: "utf8",
  }).status,
  0,
);
assert.ok(
  validateConfig({ ...base, githubMirrorPrefix: "http://ghproxy.net/https://github.com/" })
    .githubMirrorPrefix,
);
assert.ok(
  validateConfig({ ...base, githubMirrorPrefix: "https://ghproxy.net/" })
    .githubMirrorPrefix,
);
assert.ok(
  validateConfig({ ...base, githubMirrorPrefix: "https://user@ghproxy.net/https://github.com/" })
    .githubMirrorPrefix,
);
assert.ok(
  validateConfig({ ...base, versionMode: "release", release: "1.2.3" }).release,
);
assert.equal(
  validateConfig({ ...base, coordinatorUrl: "http://coordinator.example.net" })
    .coordinatorUrl,
  "远程 Coordinator 必须使用 HTTPS",
);
assert.ok(validateConfig({ ...base, coordinatorUrl: "" }).coordinatorUrl);
assert.ok(
  validateConfig({
    ...base,
    coordinatorUrl: "https://user:pass@coord.example.net",
  }).coordinatorUrl,
);
assert.ok(validateConfig({ ...base, networkId: "bad" }).networkId);
assert.ok(validateConfig({ ...base, instance: "../oops" }).instance);
assert.ok(validateConfig({ ...base, arch: "armv7" }).arch);
assert.ok(validateConfig({ ...base, relayServer: "bad host;id" }).relayServer);
assert.ok(
  validateConfig({ ...base, relayServer: "relay.example.net:70000" })
    .relayServer,
);
assert.ok(
  validateConfig({ ...base, coordinatorCa: "$(touch /tmp/x)" }).coordinatorCa,
);
assert.ok(
  validateConfig({ ...base, coordinatorCa: "relative/ca.pem" }).coordinatorCa,
);
assert.throws(() => generateScript({ ...base, networkId: "x" }), /修正配置/);

const generatedId = generateNetworkId({
  getRandomValues(bytes) {
    bytes.fill(0);
    return bytes;
  },
});
assert.equal(generatedId, "00000000-0000-4000-8000-000000000000");
const networkSetup = {
  networkId: generatedId,
  coordinatorUrl: base.coordinatorUrl,
  name: "office mesh",
  cidr: "10.77.0.0/24",
};
assert.deepEqual(validateNetworkSetup(networkSetup), {});
assert.ok(
  validateNetworkSetup({ ...networkSetup, coordinatorUrl: "" }).coordinatorUrl,
);
const createCommand = generateNetworkCreateCommand(networkSetup);
assert.match(
  createCommand,
  /--network-id '00000000-0000-4000-8000-000000000000'/,
);
assert.match(createCommand, /--cidr '10\.77\.0\.0\/24'/);
assert.ok(validateNetworkSetup({ ...networkSetup, cidr: "8.8.8.0/24" }).cidr);
assert.ok(validateNetworkSetup({ ...networkSetup, cidr: "10.77.0.1/24" }).cidr);
assert.ok(validateNetworkSetup({ ...networkSetup, cidr: "10.77.0.0/31" }).cidr);
const quotedNameCommand = generateNetworkCreateCommand({
  ...networkSetup,
  name: "lab'; touch /tmp/unexpected",
});
assert.match(quotedNameCommand, /'lab'\\''; touch \/tmp\/unexpected'/);
assert.equal(
  spawnSync("bash", ["-n"], { input: createCommand, encoding: "utf8" }).status,
  0,
);
console.log("site generator tests passed");
