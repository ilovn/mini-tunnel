const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const INSTANCE = /^[a-zA-Z0-9_-]{1,48}$/;
const ENDPOINT = /^(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}$/;
const validEndpoint = (value) =>
  ENDPOINT.test(value) &&
  Number(value.slice(value.lastIndexOf(":") + 1)) > 0 &&
  Number(value.slice(value.lastIndexOf(":") + 1)) <= 65535;

export function generateNetworkId(randomSource = globalThis.crypto) {
  if (typeof randomSource?.randomUUID === "function")
    return randomSource.randomUUID();
  const bytes = randomSource.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}

export function validateNetworkSetup({
  networkId,
  coordinatorUrl,
  name,
  cidr,
  coordinatorCa = "",
}) {
  const errors = {};
  let parsed;
  try {
    parsed = new URL(coordinatorUrl);
  } catch {
    errors.coordinatorUrl = "请输入有效的 Coordinator URL";
  }
  if (parsed && !["https:", "http:"].includes(parsed.protocol))
    errors.coordinatorUrl = "Coordinator URL 必须使用 HTTP 或 HTTPS";
  if (
    parsed &&
    parsed.protocol === "http:" &&
    !["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)
  )
    errors.coordinatorUrl = "远程 Coordinator 必须使用 HTTPS";
  if (
    parsed &&
    (parsed.username || parsed.password || parsed.search || parsed.hash)
  )
    errors.coordinatorUrl = "URL 不应包含账号密码、查询参数或片段";
  if (!UUID.test(networkId || ""))
    errors.networkId = "请先生成有效的 UUID 网络 ID";
  if (
    !name ||
    new TextEncoder().encode(name).length > 64 ||
    /[\u0000-\u001f\u007f]/.test(name)
  )
    errors.name = "网络名称需为 1–64 字节，且不能含控制字符";
  if (!isPrivateNetworkCidr(cidr))
    errors.cidr = "请输入 RFC1918 私网网段，掩码范围 /16–/30";
  if (
    coordinatorCa &&
    (!coordinatorCa.startsWith("/") ||
      !/^[a-zA-Z0-9_./-]+$/.test(coordinatorCa))
  )
    errors.coordinatorCa = "请输入目标机器上的绝对 CA 文件路径";
  return errors;
}

function isPrivateNetworkCidr(cidr) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(
    cidr || "",
  );
  if (!match) return false;
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((part) => part > 255) || prefix < 16 || prefix > 30)
    return false;
  const privateAddress =
    octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168);
  const address =
    (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return privateAddress && (address & mask) >>> 0 === address;
}

export function generateNetworkCreateCommand(config) {
  const errors = validateNetworkSetup(config);
  if (Object.keys(errors).length) throw new Error("请先修正网络创建参数");
  const parts = [];
  if (config.coordinatorCa)
    parts.push(
      `MINI_TUNNEL_COORDINATOR_CA_CERT_FILE=${sh(config.coordinatorCa)}`,
    );
  parts.push("mini-tunnel network create");
  parts.push(`--name ${sh(config.name)}`);
  parts.push(`--cidr ${sh(config.cidr)}`);
  parts.push(`--network-id ${sh(config.networkId)}`);
  parts.push(`--coordinator-url ${sh(config.coordinatorUrl)}`);
  return parts.join(" \\\n  ");
}

export function validateConfig(config) {
  const errors = {};
  let parsed;
  try {
    parsed = new URL(config.coordinatorUrl);
  } catch {
    errors.coordinatorUrl = "请输入有效的 Coordinator URL";
  }
  if (parsed && !["https:", "http:"].includes(parsed.protocol))
    errors.coordinatorUrl = "仅支持 HTTPS；HTTP 仅允许本机调试地址";
  if (
    parsed &&
    parsed.protocol === "http:" &&
    !["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)
  )
    errors.coordinatorUrl = "远程 Coordinator 必须使用 HTTPS";
  if (
    parsed &&
    (parsed.username || parsed.password || parsed.search || parsed.hash)
  )
    errors.coordinatorUrl = "URL 不应包含账号密码、查询参数或片段";
  if (!UUID.test(config.networkId || ""))
    errors.networkId = "请输入有效的网络 UUID";
  if (!INSTANCE.test(config.instance || ""))
    errors.instance = "实例名仅允许字母、数字、下划线和短横线，最长 48 位";
  if (!["ubuntu", "systemd", "macos"].includes(config.platform))
    errors.platform = "请选择支持的目标平台";
  if (!["auto", "x86_64", "aarch64"].includes(config.arch))
    errors.arch = "请选择支持的架构";
  if (!["latest", "release"].includes(config.versionMode))
    errors.versionMode = "请选择发行版本";
  if (
    config.versionMode === "release" &&
    !/^v[0-9][A-Za-z0-9.+-]*$/.test(config.release || "")
  )
    errors.release = "版本格式示例：v1.2.3";
  for (const key of ["relayServer", "udpRelayServer"]) {
    if (config[key] && !validEndpoint(config[key]))
      errors[key] = "请输入有效端口（1–65535），例如 relay.example.com:42001";
  }
  if (config.stunServer && !validEndpoint(config.stunServer))
    errors.stunServer = "请输入主机名或 IP 加有效端口（1–65535）";
  if (config.githubMirrorPrefix) {
    let mirror;
    try {
      mirror = new URL(config.githubMirrorPrefix);
    } catch {
      errors.githubMirrorPrefix = "请输入 HTTPS GitHub 镜像前缀";
    }
    if (
      mirror &&
      (mirror.protocol !== "https:" ||
        !mirror.hostname ||
        mirror.username ||
        mirror.password ||
        mirror.search ||
        mirror.hash ||
        /[\s\u0000-\u001f\u007f]/.test(config.githubMirrorPrefix) ||
        mirror.href !== config.githubMirrorPrefix ||
        !config.githubMirrorPrefix.endsWith("/https://github.com/"))
    )
      errors.githubMirrorPrefix =
        "镜像前缀需以 /https://github.com/ 结尾，且不能包含账号、参数或片段";
  }
  if (
    config.coordinatorCa &&
    (!config.coordinatorCa.startsWith("/") ||
      !/^[a-zA-Z0-9_./-]+$/.test(config.coordinatorCa))
  )
    errors.coordinatorCa = "请输入目标服务器上的绝对文件路径";
  return errors;
}

const sh = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;

export function generateScript(config) {
  const errors = validateConfig(config);
  if (Object.keys(errors).length) throw new Error("请先修正配置项");
  const release = config.versionMode === "release" ? config.release : "latest";
  const args = [
    "--release",
    release,
    "--arch",
    config.arch,
    "--repo",
    "ilovn/mini-tunnel",
    "--",
    "--network-id",
    config.networkId,
    "--coordinator-url",
    config.coordinatorUrl,
    "--invite-token-file",
    '"$invite_file"',
    "--instance",
    config.instance,
    "--stun-server",
    config.stunServer || "111.206.174.2:3478",
  ];
  if (config.relayServer) args.push("--relay-server", config.relayServer);
  if (config.udpRelayServer)
    args.push("--udp-relay-server", config.udpRelayServer);
  if (config.coordinatorCa) args.push("--coordinator-ca", config.coordinatorCa);
  const shellArgs = args
    .map((arg) => (arg === '"$invite_file"' ? '"$invite_file"' : sh(arg)))
    .join(" \\\n  ");
  const mirrorPrefix = config.githubMirrorPrefix || "";
  const platform = config.platform === "macos" ? "macos" : "linux";
  const platformLabel = platform === "macos" ? "macOS LaunchDaemon" : "Linux systemd";
  const platformPrerequisite = platform === "macos"
    ? `[[ "$(uname -s)" == Darwin ]] || { echo 'This installer requires macOS.' >&2; exit 1; }
command -v launchctl >/dev/null 2>&1 || { echo 'launchctl is required.' >&2; exit 1; }`
    : `[[ "$(uname -s)" == Linux ]] || { echo 'This installer requires Linux.' >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo 'This installer requires systemd.' >&2; exit 1; }
[[ -c /dev/net/tun ]] || { echo '/dev/net/tun is unavailable; enable TUN on this host.' >&2; exit 1; }`;
  return `#!/usr/bin/env bash
set -Eeuo pipefail

# Generated by mini-tunnel setup. ${platformLabel} peer installer.
# The one-use invite is requested at runtime and is never embedded in this file.
# Source: ${config.coordinatorMode === "custom" ? "custom Coordinator" : "existing Coordinator"}

for command in git gh curl python3 tar gzip; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'Missing prerequisite: %s\\n' "$command" >&2
    printf 'Install Git, GitHub CLI (gh), curl, Python 3, tar, and gzip, then retry.\\n' >&2
    exit 1
  }
done
${platformPrerequisite}
gh attestation verify --help >/dev/null 2>&1 || {
  echo "GitHub CLI (gh) must support 'attestation verify'; upgrade gh and retry." >&2
  exit 1
}

umask 077
tmp_dir=$(mktemp -d "\${TMPDIR:-/tmp}/mini-tunnel-setup.XXXXXX")
cleanup() { rm -rf -- "$tmp_dir"; }
trap cleanup EXIT
invite_file="$tmp_dir/invite.token"
read -r -s -p 'Paste one-use invite token (input hidden): ' invite_token
printf '\\n'
[[ -n "$invite_token" ]] || { echo 'Invite token cannot be empty.' >&2; exit 1; }
printf '%s' "$invite_token" > "$invite_file"
unset invite_token
chmod 0600 "$invite_file"

github_mirror_prefix=${sh(mirrorPrefix)}
if [[ -n "$github_mirror_prefix" ]]; then
  export MINI_TUNNEL_GITHUB_MIRROR_PREFIX="$github_mirror_prefix"
  repository_url="\${github_mirror_prefix}ilovn/mini-tunnel.git"
else
  repository_url=https://github.com/ilovn/mini-tunnel.git
fi
git clone --quiet --depth 1 "$repository_url" "$tmp_dir/mini-tunnel"
cd "$tmp_dir/mini-tunnel"
./deploy/quick-install-peer.sh \\
  '--platform' ${sh(platform)} \\
  ${shellArgs}
`;
}
