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
  if (!["ubuntu", "systemd", "macos", "windows"].includes(config.platform))
    errors.platform = "请选择支持的目标平台";
  if (!["auto", "x86_64", "aarch64"].includes(config.arch))
    errors.arch = "请选择支持的架构";
  const statusListen = config.statusListen || "127.0.0.1:42003";
  if (!/^127\.0\.0\.1:[0-9]{1,5}$|^\[::1\]:[0-9]{1,5}$/.test(statusListen) || !validEndpoint(statusListen))
    errors.statusListen = "状态监听地址必须使用本机回环地址和有效端口";
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
  if (config.coordinatorCa) {
    const windowsCaPath = /^[a-zA-Z]:[\\/][^\u0000-\u001f\u007f]+$/.test(
      config.coordinatorCa,
    );
    const unixCaPath =
      config.coordinatorCa.startsWith("/") &&
      /^[a-zA-Z0-9_./-]+$/.test(config.coordinatorCa);
    if (config.platform === "windows" ? !windowsCaPath : !unixCaPath)
      errors.coordinatorCa = "请输入目标机器上的有效绝对 CA 文件路径";
  }
  return errors;
}

const sh = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;

export function generateScript(config) {
  const errors = validateConfig(config);
  if (Object.keys(errors).length) throw new Error("请先修正配置项");
  if (config.platform === "windows") return generateWindowsScript(config);
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
    "--status-listen",
    config.statusListen || "127.0.0.1:42003",
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

function generateWindowsScript(config) {
  const settings = {
    coordinatorUrl: config.coordinatorUrl,
    networkId: config.networkId,
    instance: config.instance,
    arch: config.arch,
    versionMode: config.versionMode,
    release: config.versionMode === "release" ? config.release : "latest",
    stunServer: config.stunServer || "111.206.174.2:3478",
    statusListen: config.statusListen || "127.0.0.1:42003",
    relayServer: config.relayServer || "",
    udpRelayServer: config.udpRelayServer || "",
    coordinatorCa: config.coordinatorCa || "",
    githubMirrorPrefix: config.githubMirrorPrefix || "",
  };
  const settingsJson = JSON.stringify(settings).replaceAll("'", "''");
  return `# mini-tunnel Windows Service Control Manager peer installer.
param(
  [switch]$Status,
  [switch]$Restart,
  [switch]$Uninstall,
  [switch]$RemoveState,
  [string]$WintunArchivePath
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Setup = ConvertFrom-Json -InputObject '${settingsJson}'
$ServiceName = "mini-tunnel-peer-$($Setup.instance)"
$InstallDir = Join-Path $env:ProgramFiles "mini-tunnel\\$($Setup.instance)"
$StateDir = Join-Path $env:ProgramData "mini-tunnel\\$($Setup.instance)"
$ConfigPath = Join-Path $StateDir 'service.json'
$BinaryPath = Join-Path $InstallDir 'mini-tunnel.exe'
$StatusListen = $Setup.statusListen
$LogPath = Join-Path $StateDir 'service.log'
$WintunArchiveSha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
$WintunArchiveUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip'

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator and run this script again.'
  }
}

function Get-GitHubUrl([string]$Path) {
  if ($Setup.githubMirrorPrefix) { return "$($Setup.githubMirrorPrefix)$Path" }
  return "https://github.com/$Path"
}

function Get-ApiJson([string]$Path) {
  return Invoke-RestMethod -UseBasicParsing -Headers @{ 'Accept' = 'application/vnd.github+json'; 'User-Agent' = 'mini-tunnel-setup' } -Uri "https://api.github.com/$Path" -TimeoutSec 30
}

function Resolve-ReleaseTag {
  if ($Setup.versionMode -eq 'release') { return [string]$Setup.release }
  return [string](Get-ApiJson 'repos/ilovn/mini-tunnel/releases/latest').tag_name
}

function Resolve-TagCommit([string]$Tag) {
  $tagRef = [Uri]::EscapeDataString($Tag)
  $object = (Get-ApiJson "repos/ilovn/mini-tunnel/git/ref/tags/$tagRef").object
  for ($depth = 0; $depth -lt 10; $depth++) {
    if ($object.type -eq 'commit' -and $object.sha -match '^[0-9a-fA-F]{40}$') { return $object.sha.ToLowerInvariant() }
    if ($object.type -ne 'tag' -or $object.sha -notmatch '^[0-9a-fA-F]{40}$') { break }
    $object = (Get-ApiJson "repos/ilovn/mini-tunnel/git/tags/$($object.sha)").object
  }
  throw 'Could not resolve the release tag to a commit.'
}

function Assert-ReleaseArchive([string]$ArchivePath, [string]$ArchiveName, [string]$Tag, [string]$Commit) {
  $checksumUri = Get-GitHubUrl "ilovn/mini-tunnel/releases/download/$Tag/$ArchiveName.sha256"
  $checksum = (Invoke-WebRequest -UseBasicParsing -Uri $checksumUri -TimeoutSec 60).Content.Trim()
  $pattern = '^([0-9a-fA-F]{64})[ \\t]+\\*?' + [regex]::Escape($ArchiveName) + '$'
  if ($checksum -notmatch $pattern) { throw 'Release checksum sidecar is malformed.' }
  $expected = $Matches[1].ToLowerInvariant()
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArchivePath).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw 'Release checksum does not match the downloaded archive.' }
  $env:GH_PROMPT_DISABLED = '1'
  & gh attestation verify $ArchivePath --repo ilovn/mini-tunnel --signer-workflow ilovn/mini-tunnel/.github/workflows/release.yml --source-ref "refs/tags/$Tag" --source-digest $Commit --deny-self-hosted-runners
  if ($LASTEXITCODE -ne 0) { throw 'GitHub Sigstore provenance verification failed.' }
}

function Get-TargetArchitecture {
  $native = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
  switch ($native) {
    'X64' { return 'x86_64' }
    'Arm64' { return 'aarch64' }
    default { throw "Unsupported Windows architecture: $native" }
  }
}

function Get-WintunDll([string]$ArchivePath, [string]$Architecture, [string]$Destination) {
  if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) { throw 'Wintun archive does not exist.' }
  $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArchivePath).Hash.ToLowerInvariant()
  if ($digest -ne $WintunArchiveSha256) { throw 'Wintun archive checksum does not match the pinned official release.' }
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
  try {
    $wanted = if ($Architecture -eq 'aarch64') { 'wintun/bin/arm64/wintun.dll' } else { 'wintun/bin/amd64/wintun.dll' }
    $entry = $zip.Entries | Where-Object { $_.FullName -eq $wanted } | Select-Object -First 1
    if (-not $entry -or $entry.Length -le 0 -or $entry.Length -gt 4MB) { throw "Official Wintun DLL missing or oversized: $wanted" }
    $input = $entry.Open()
    try {
      $output = [IO.File]::Create($Destination)
      try { $input.CopyTo($output) } finally { $output.Dispose() }
    } finally { $input.Dispose() }
  } finally { $zip.Dispose() }
}

function Set-PrivateDirectoryAcl([string]$Path) {
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
    $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    [void]$acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Wait-PeerReady([int]$Seconds = 30) {
  $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
      try {
        $null = Invoke-RestMethod -UseBasicParsing -Uri "http://$StatusListen/status" -TimeoutSec 2
        return
      } catch { Start-Sleep -Seconds 1 }
    } else { Start-Sleep -Seconds 1 }
  }
  throw "Peer service did not become ready. Inspect $LogPath and Windows service status."
}

function Show-ServiceStatus {
  Get-Service -Name $ServiceName -ErrorAction Stop | Format-List Name,Status,StartType
  try { Invoke-RestMethod -UseBasicParsing -Uri "http://$StatusListen/status" -TimeoutSec 5 | ConvertTo-Json -Depth 8 }
  catch { Write-Warning "Peer status endpoint is unavailable. Read $LogPath." }
}

function Remove-PeerService {
  Assert-Administrator
  $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Windows could not remove the peer service.' }
  }
  if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
  if ($RemoveState -and (Test-Path -LiteralPath $StateDir)) {
    Write-Warning 'Removing local identity and state. Revoke this device in the Coordinator first.'
    Remove-Item -LiteralPath $StateDir -Recurse -Force
  }
  if ($RemoveState) { Write-Host "Removed $ServiceName and its local state." }
  else { Write-Host "Removed $ServiceName and its binary; identity/state remain at $StateDir." }
}

if ($Status) { Show-ServiceStatus; exit 0 }
if ($Restart) { Assert-Administrator; Restart-Service -Name $ServiceName -Force; Wait-PeerReady; Show-ServiceStatus; exit 0 }
if ($Uninstall) { Remove-PeerService; exit 0 }
if ($RemoveState) { throw 'Use -RemoveState only with -Uninstall.' }
Assert-Administrator
if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'PowerShell 5.1 or later is required.' }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'Install GitHub CLI (gh) with attestation support, then retry.' }
& gh attestation verify --help *> $null
if ($LASTEXITCODE -ne 0) { throw "GitHub CLI must support 'gh attestation verify'." }
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw "Service already exists: $ServiceName. Use -Status, -Restart, or -Uninstall." }
if (Test-Path -LiteralPath $InstallDir) { throw "Install directory already exists: $InstallDir. Inspect it before retrying." }

$Architecture = Get-TargetArchitecture
if ($Setup.arch -ne 'auto' -and $Setup.arch -ne $Architecture) { throw "Selected architecture $($Setup.arch) does not match this Windows host ($Architecture)." }
$sourceCaPath = $null
if ($Setup.coordinatorCa) {
  if (-not (Test-Path -LiteralPath $Setup.coordinatorCa -PathType Leaf)) { throw 'Coordinator CA file is missing.' }
  $caItem = Get-Item -LiteralPath $Setup.coordinatorCa -Force
  if ($caItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Coordinator CA path must not be a reparse point.' }
  $sourceCaPath = $caItem.FullName
}
$ArchiveName = "mini-tunnel-windows-$Architecture.zip"
$TempDir = Join-Path ([IO.Path]::GetTempPath()) ("mini-tunnel-setup-" + [guid]::NewGuid().ToString('N'))
$TokenPath = Join-Path $TempDir 'invite.token'
$CreatedState = -not (Test-Path -LiteralPath $StateDir)
$ServiceCreated = $false
try {
  New-Item -ItemType Directory -Path $TempDir | Out-Null
  Set-PrivateDirectoryAcl $TempDir
  $ReleaseTag = Resolve-ReleaseTag
  if ($ReleaseTag -notmatch '^v[0-9][A-Za-z0-9.+-]*$') { throw "Unsupported release tag: $ReleaseTag" }
  $SourceCommit = Resolve-TagCommit $ReleaseTag
  $ArchivePath = Join-Path $TempDir $ArchiveName
  Invoke-WebRequest -UseBasicParsing -Uri (Get-GitHubUrl "ilovn/mini-tunnel/releases/download/$ReleaseTag/$ArchiveName") -OutFile $ArchivePath -TimeoutSec 180
  Assert-ReleaseArchive $ArchivePath $ArchiveName $ReleaseTag $SourceCommit
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $peerZip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
  try {
    if ($peerZip.Entries.Count -ne 1 -or $peerZip.Entries[0].FullName -ne 'mini-tunnel.exe' -or $peerZip.Entries[0].Length -gt 100MB) { throw 'Peer archive contains unexpected or oversized files.' }
    $input = $peerZip.Entries[0].Open()
    try {
      $stagedBinary = Join-Path $TempDir 'mini-tunnel.exe'
      $output = [IO.File]::Create($stagedBinary)
      try { $input.CopyTo($output) } finally { $output.Dispose() }
    } finally { $input.Dispose() }
  } finally { $peerZip.Dispose() }
  & $stagedBinary --help *> $null
  if ($LASTEXITCODE -ne 0) { throw 'Downloaded peer binary cannot run on this Windows host.' }
  & $stagedBinary windows-service-host --help *> $null
  if ($LASTEXITCODE -ne 0) { throw 'This Windows release does not contain the SCM service host yet. Use a release published after Windows service support is included.' }

  $wintunPath = $WintunArchivePath
  if (-not $wintunPath) {
    $wintunPath = Join-Path $TempDir 'wintun-0.14.1.zip'
    Invoke-WebRequest -UseBasicParsing -Uri $WintunArchiveUrl -OutFile $wintunPath -TimeoutSec 180
  }
  $stagedWintun = Join-Path $TempDir 'wintun.dll'
  Get-WintunDll $wintunPath $Architecture $stagedWintun

  if (-not (Test-Path -LiteralPath $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
  } else {
    $stateItem = Get-Item -LiteralPath $StateDir -Force
    if ($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State directory must not be a reparse point.' }
    if (-not (Test-Path -LiteralPath (Join-Path $StateDir 'device.key')) -or -not (Test-Path -LiteralPath (Join-Path $StateDir 'install.json'))) {
      throw "Existing state is incomplete at $StateDir; refusing to create a second identity."
    }
    $marker = Get-Content -LiteralPath (Join-Path $StateDir 'install.json') -Raw | ConvertFrom-Json
    if ($marker.network_id -ne $Setup.networkId -or $marker.coordinator_url -ne $Setup.coordinatorUrl) {
      throw 'Existing device identity belongs to another network or Coordinator.'
    }
  }
  Set-PrivateDirectoryAcl $StateDir

  if ($CreatedState) {
    $secureToken = Read-Host -Prompt 'Paste one-use invite token (input hidden)' -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secureToken)
    $tokenBytes = $null
    $tokenChars = $null
    try {
      $tokenChars = New-Object char[] $secureToken.Length
      for ($i = 0; $i -lt $tokenChars.Length; $i++) { $tokenChars[$i] = [char][Runtime.InteropServices.Marshal]::ReadInt16($ptr, $i * 2) }
      $tokenBytes = [Text.UTF8Encoding]::new($false).GetBytes($tokenChars)
      [IO.File]::WriteAllBytes($TokenPath, $tokenBytes)
    } finally {
      if ($tokenChars) { [Array]::Clear($tokenChars, 0, $tokenChars.Length) }
      if ($tokenBytes) { [Array]::Clear($tokenBytes, 0, $tokenBytes.Length) }
      [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
      $secureToken.Dispose()
    }
    $tokenAcl = [Security.AccessControl.FileSecurity]::new()
    $tokenAcl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in @(([Security.Principal.WindowsIdentity]::GetCurrent().User.Value), 'S-1-5-18')) {
      $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
      $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow')
      [void]$tokenAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $TokenPath -AclObject $tokenAcl
    $oldStateRoot = $env:MINI_TUNNEL_STATE_DIR
    $oldCoordinatorCa = $env:MINI_TUNNEL_COORDINATOR_CA_CERT_FILE
    $env:MINI_TUNNEL_STATE_DIR = $StateDir
    if ($sourceCaPath) { $env:MINI_TUNNEL_COORDINATOR_CA_CERT_FILE = $sourceCaPath }
    else { Remove-Item Env:MINI_TUNNEL_COORDINATOR_CA_CERT_FILE -ErrorAction SilentlyContinue }
    try {
      & $stagedBinary network join --network-id $Setup.networkId --coordinator-url $Setup.coordinatorUrl --invite-token-file $TokenPath
      if ($LASTEXITCODE -ne 0) { throw 'Network enrollment failed; the invite was not written to logs.' }
    } finally {
      $env:MINI_TUNNEL_STATE_DIR = $oldStateRoot
      $env:MINI_TUNNEL_COORDINATOR_CA_CERT_FILE = $oldCoordinatorCa
      if (Test-Path -LiteralPath $TokenPath) { Remove-Item -LiteralPath $TokenPath -Force }
    }
    $markerPath = Join-Path $StateDir 'install.json'
    [IO.File]::WriteAllText($markerPath, (@{ network_id = $Setup.networkId; coordinator_url = $Setup.coordinatorUrl } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    Set-PrivateDirectoryAcl $StateDir
  }

  if ($sourceCaPath) {
    $caPath = Join-Path $StateDir 'coordinator-ca.pem'
    Copy-Item -LiteralPath $sourceCaPath -Destination $caPath -Force
  } else { $caPath = $null }

  New-Item -ItemType Directory -Path $InstallDir | Out-Null
  Copy-Item -LiteralPath $stagedBinary -Destination $BinaryPath
  Copy-Item -LiteralPath $stagedWintun -Destination (Join-Path $InstallDir 'wintun.dll')
  $arguments = @('--state-dir', $StateDir, 'peer', 'tunnel', 'mesh', '--network-id', $Setup.networkId, '--coordinator-url', $Setup.coordinatorUrl, '--stun-server', $Setup.stunServer, '--ice', '--manage-route')
  if ($Setup.relayServer) { $arguments += @('--relay-server', $Setup.relayServer) }
  if ($Setup.udpRelayServer) { $arguments += @('--udp-relay-server', $Setup.udpRelayServer) }
  $serviceConfig = @{ arguments = $arguments; log_file = $LogPath; status_listen = $StatusListen; coordinator_ca = $caPath }
  [IO.File]::WriteAllText($ConfigPath, ($serviceConfig | ConvertTo-Json -Depth 4 -Compress), [Text.UTF8Encoding]::new($false))
  Set-PrivateDirectoryAcl $StateDir
  $imagePath = '"' + $BinaryPath + '" windows-service-host --service-name ' + $ServiceName + ' --config "' + $ConfigPath + '"'
  New-Service -Name $ServiceName -DisplayName "mini-tunnel peer ($($Setup.instance))" -Description 'Authenticated mini-tunnel peer mesh' -BinaryPathName $imagePath -StartupType Automatic | Out-Null
  $ServiceCreated = $true
  & sc.exe failure $ServiceName reset= 86400 actions= 'restart/5000/restart/15000/restart/60000' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not configure bounded Windows service recovery actions.' }
  Start-Service -Name $ServiceName
  Wait-PeerReady
  Write-Host "Installed and started $ServiceName ($Architecture)."
  Write-Host "Status:   .\\mini-tunnel-$($Setup.instance).ps1 -Status"
  Write-Host "Restart:  .\\mini-tunnel-$($Setup.instance).ps1 -Restart"
  Write-Host "Uninstall: .\\mini-tunnel-$($Setup.instance).ps1 -Uninstall"
  Write-Host "Logs:     $LogPath"
} catch {
  if ($ServiceCreated) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
  }
  if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
  if ($CreatedState -and -not (Test-Path -LiteralPath (Join-Path $StateDir 'install.json'))) {
    Remove-Item -LiteralPath $StateDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  throw
} finally {
  if (Test-Path -LiteralPath $TempDir) { Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue }
}
`;
}
