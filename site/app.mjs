import {
  generateNetworkCreateCommand,
  generateNetworkId,
  generateScript,
  validateConfig,
  validateNetworkSetup,
} from "./generator.mjs";

const $ = (id) => document.getElementById(id);
const form = $("config-form");
const ids = [
  "platform",
  "coordinatorUrl",
  "networkId",
  "instance",
  "arch",
  "versionMode",
  "release",
  "stunServer",
  "relayServer",
  "udpRelayServer",
  "coordinatorCa",
  "githubMirrorPrefix",
];
const config = () => ({
  ...Object.fromEntries(ids.map((id) => [id, $(id).value.trim()])),
  coordinatorMode: document.querySelector(
    'input[name="coordinatorMode"]:checked',
  ).value,
});
const renderErrors = (errors) => {
  document.querySelectorAll("[data-error]").forEach((node) => {
    node.textContent = "";
  });
  Object.entries(errors).forEach(([key, message]) => {
    const node = document.querySelector(`[data-error="${key}"]`);
    if (node) node.textContent = message;
  });
};
const updatePreview = () => {
  const value = config();
  const isMacOS = value.platform === "macos";
  $("platform-help").textContent = isMacOS
    ? "需要 macOS、管理员权限和 TUN 支持"
    : "需要 systemd 247+ 和 TUN 设备";
  $("platform-badge").textContent = isMacOS
    ? "签名验证 · 安全安装 · LaunchDaemon 托管"
    : "签名验证 · 安全安装 · systemd 托管";
  $("result-platform-help").textContent = isMacOS
    ? "下载到目标 macOS 设备后，以管理员权限运行。"
    : "下载到目标 Linux 服务器后按说明运行。";
  $("result-prerequisites").textContent = isMacOS
    ? "运行前请检查脚本。目标 Mac 需安装 git、支持 attestation verify 的 GitHub CLI（gh）、curl、Python 3、tar 和 gzip，并需管理员权限。"
    : "运行前请检查脚本。目标 Linux 需安装 git、支持 attestation verify 的 GitHub CLI（gh）、curl、Python 3、tar 和 gzip，并启用 systemd 与 TUN。";
  const documentation = $("platform-doc-link");
  documentation.href = isMacOS
    ? "https://github.com/ilovn/mini-tunnel/blob/main/deploy/macos/README.md"
    : "https://github.com/ilovn/mini-tunnel/blob/main/deploy/systemd/README.md";
  documentation.textContent = isMacOS ? "阅读 macOS 部署文档 ↗" : "阅读 Linux 部署文档 ↗";
  $("release-field").classList.toggle(
    "hidden",
    value.versionMode !== "release",
  );
  const ready = !Object.keys(validateConfig(value)).length;
  const targetPlatform = value.platform === "macos" ? "macos" : "linux";
  $("preview").innerHTML = ready
    ? '<span class="code-muted"># 预构建版本 · 自动验签</span><br><span class="code-purple">quick-install-peer.sh</span> <span class="code-blue">--platform</span> ' +
      targetPlatform + ' <span class="code-blue">--release</span> ' +
      (value.versionMode === "release" ? escapeHtml(value.release) : "latest") +
      '<br><span class="code-muted"># 邀请 token 运行时输入</span>'
    : '<span class="code-muted"># 填写 Coordinator 与网络 ID</span><br><span class="code-purple">mini-tunnel</span> <span class="code-blue">peer setup</span><br><span class="code-muted"># token 在运行时安全输入</span>';
};
const updateNetworkCommand = () => {
  const values = {
    networkId: $("networkId").value.trim(),
    coordinatorUrl: $("coordinatorUrl").value.trim(),
    name: $("networkName").value.trim(),
    cidr: $("networkCidr").value.trim(),
    coordinatorCa: $("coordinatorCa").value.trim(),
  };
  const errors = validateNetworkSetup(values);
  $("network-command").textContent = Object.keys(errors).length
    ? "生成网络 UUID 并填写有效的 Coordinator、网络名称和私网网段"
    : generateNetworkCreateCommand(values);
  $("copy-network-command").disabled = Object.keys(errors).length > 0;
  for (const [key, id] of [
    ["name", "networkName"],
    ["cidr", "networkCidr"],
  ]) {
    const error = document.querySelector(`[data-error="${key}"]`);
    if (error) error.textContent = errors[key] || "";
  }
};
const escapeHtml = (value) =>
  value.replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
form.addEventListener("input", () => {
  updatePreview();
  updateNetworkCommand();
});
form.addEventListener("change", (event) => {
  updatePreview();
  updateNetworkCommand();
  if (event.target.name === "coordinatorMode") {
    const note = $("coordinator-help");
    note.textContent =
      event.target.value === "custom"
        ? "填写自建或私有部署的 Coordinator；私有 CA 可在高级选项指定。"
        : "填写管理员提供的 Coordinator 地址。";
  }
});
$("generate-id-button").addEventListener("click", () => {
  $("networkId").value = generateNetworkId();
  updatePreview();
  updateNetworkCommand();
});
$("copy-network-command").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("network-command").textContent);
  $("copy-network-command").textContent = "已复制 ✓";
  setTimeout(() => {
    $("copy-network-command").textContent = "复制命令";
  }, 1800);
});
form.addEventListener("submit", (event) => {
  event.preventDefault();
  const value = config();
  const errors = validateConfig(value);
  renderErrors(errors);
  if (Object.keys(errors).length) {
    $(Object.keys(errors)[0]).focus();
    return;
  }
  const script = generateScript(value);
  $("script-output").textContent = script;
  $("result").classList.remove("hidden");
  $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
});
$("copy-button").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("script-output").textContent);
  $("copy-button").textContent = "已复制 ✓";
  setTimeout(() => {
    $("copy-button").textContent = "复制脚本";
  }, 1800);
});
$("download-button").addEventListener("click", () => {
  const blob = new Blob([$("script-output").textContent], {
    type: "text/x-shellscript;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `mini-tunnel-${$("platform").value}-${$("instance").value.trim()}.sh`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
form.addEventListener("reset", renderErrors);
updatePreview();
updateNetworkCommand();
