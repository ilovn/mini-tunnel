import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateScript, validateConfig } from "./generator.mjs";

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
};
assert.deepEqual(validateConfig(base), {});
assert.match(generateScript(base), /'--arch'[\s\\]+\s+'x86_64'/);
assert.match(generateScript(base), /read -r -s/);
assert.match(
  generateScript(base),
  /'--invite-token-file'[\s\\]+\s+"\$invite_file"/,
);
assert.doesNotMatch(generateScript(base), /test-invite-secret/);
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
assert.ok(
  validateConfig({ ...base, versionMode: "release", release: "1.2.3" }).release,
);
assert.equal(
  validateConfig({ ...base, coordinatorUrl: "http://coordinator.example.net" })
    .coordinatorUrl,
  "远程 Coordinator 必须使用 HTTPS",
);
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
console.log("site generator tests passed");
