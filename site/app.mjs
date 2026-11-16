import { generateScript, validateConfig } from "./generator.mjs";

const $ = (id) => document.getElementById(id);
const form = $("config-form");
const ids = [
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
  $("release-field").classList.toggle(
    "hidden",
    value.versionMode !== "release",
  );
  const ready = !Object.keys(validateConfig(value)).length;
  $("preview").innerHTML = ready
    ? '<span class="code-muted"># 预构建版本 · 自动验签</span><br><span class="code-purple">quick-install-peer.sh</span> <span class="code-blue">--release</span> ' +
      (value.versionMode === "release" ? escapeHtml(value.release) : "latest") +
      '<br><span class="code-muted"># 邀请 token 运行时输入</span>'
    : '<span class="code-muted"># 填写 Coordinator 与网络 ID</span><br><span class="code-purple">mini-tunnel</span> <span class="code-blue">peer setup</span><br><span class="code-muted"># token 在运行时安全输入</span>';
};
const escapeHtml = (value) =>
  value.replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
form.addEventListener("input", updatePreview);
form.addEventListener("change", (event) => {
  updatePreview();
  if (event.target.name === "coordinatorMode") {
    const note = $("coordinator-help");
    note.textContent =
      event.target.value === "custom"
        ? "填写自建或私有部署的 Coordinator；私有 CA 可在高级选项指定。"
        : "填写管理员提供的 Coordinator 地址。";
  }
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
  anchor.download = `mini-tunnel-${$("instance").value.trim()}.sh`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
form.addEventListener("reset", renderErrors);
updatePreview();
