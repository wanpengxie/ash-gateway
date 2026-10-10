// `GET /p/<pairing code>`: the page the owner opens on a computer. It shows the one-line command
// that installs the computer program and pairs it. Public and stateless: it only echoes the code
// from the URL into a command, never checks it, and is never cached.

/**
 * Where the computer program's release installer lives (the installer then downloads the matching
 * build). The gateway's `INSTALL_SCRIPT_URL` variable overrides it; wrangler.jsonc and the bundle
 * metadata carry the same default.
 */
export const DEFAULT_INSTALL_SCRIPT_URL = "https://github.com/wanpengxie/ash/releases/download/device-v0.2.0/install.sh";

/** The URL goes into a shell command: plain https URLs only (no query, no shell characters). */
const SCRIPT_URL = /^https:\/\/[A-Za-z0-9.-]+(:\d+)?(\/[A-Za-z0-9._~%+-]*)*$/;

/** The configured installer URL, or the default when it is unset or not a plain https URL. */
export function installScriptUrl(configured?: string): string {
  const url = configured?.trim();
  return url && SCRIPT_URL.test(url) ? url : DEFAULT_INSTALL_SCRIPT_URL;
}

/** Pairing tickets are base64url; anything else is not a code and is never put into a command. */
const CODE = /^[A-Za-z0-9_-]{8,128}$/;

/** The gateway's own origin goes into a shell command: only plain host names are accepted (plain http only for local debugging). */
const ORIGIN = /^(https:\/\/[A-Za-z0-9.-]+|http:\/\/(?:localhost|127\.0\.0\.1))(:\d+)?$/;

export type Os = "mac" | "linux" | "windows" | "other";

export function detectOs(userAgent: string): Os {
  if (/Windows/i.test(userAgent)) return "windows";
  if (/Android|iPhone|iPad|iPod/i.test(userAgent)) return "other";
  if (/Macintosh|Mac OS X/i.test(userAgent)) return "mac";
  if (/Linux|X11/i.test(userAgent)) return "linux";
  return "other";
}

/** The one-line command for a system, or null when the computer program does not support it. */
export function installCommand(os: Os, origin: string, code: string, scriptUrl = DEFAULT_INSTALL_SCRIPT_URL): string | null {
  if (os === "mac" || os === "linux") return `curl -fsSL '${scriptUrl}' | sh -s -- '${origin}' '${code}'`;
  return null;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export function installPage(origin: string, code: string, userAgent: string, scriptUrl?: string): Response {
  const headers = {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "x-robots-tag": "noindex",
  };
  if (!CODE.test(code) || !ORIGIN.test(origin)) {
    return new Response(page("<h1>配对码无效</h1><p>请回到 Ash 重新生成配对码。</p>"), { status: 404, headers });
  }
  const detected = detectOs(userAgent);
  const blocks = (["mac", "linux", "windows"] as const).map((os) => {
    const cmd = installCommand(os, origin, code, installScriptUrl(scriptUrl));
    const title = os === "mac" ? "macOS" : os === "linux" ? "Linux" : "Windows";
    const body = cmd
      ? `<pre id="cmd-${os}">${esc(cmd)}</pre><button data-copy="cmd-${os}">复制</button>`
      : `<p class="muted">电脑端程序暂不支持 Windows。</p>`;
    return `<section data-os="${os}"${os === detected ? ' class="here"' : ""}><h2>${title}${os === detected ? "（当前系统）" : ""}</h2>${body}</section>`;
  });
  return new Response(page(`<h1>把这台电脑接入 Ash</h1>
<p>打开终端，粘贴下面这一行并回车。装好后回到 Ash，批准这台电脑的接入请求，并选择它可以做什么。</p>
${blocks.join("\n")}
<p class="muted">配对码只能用一次，几分钟后失效。</p>`), { headers });
}

function page(inner: string): string {
  return `<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><link rel="icon" href="data:,">
<title>Ash</title>
<style>
body{font:15px/1.6 system-ui,-apple-system,sans-serif;margin:0;background:#f6f7f9;color:#1d2430}
main{max-width:40rem;margin:8vh auto;padding:2rem;background:#fff;border-radius:14px;box-shadow:0 2px 16px #0001}
h1{font-size:1.4rem;margin:0 0 .3rem}h2{font-size:1rem;margin:1.2rem 0 .3rem}p{margin:.4rem 0;color:#4a5566}
pre{margin:.3rem 0;padding:.7rem;background:#eef1f6;border-radius:8px;white-space:pre-wrap;word-break:break-all;font-size:.9rem}
button{padding:.4rem 1rem;font-size:.9rem;border:0;border-radius:8px;background:#3d63f5;color:#fff;cursor:pointer}
.muted{font-size:.85rem;color:#7a8595}section:not(.here){opacity:.7}
</style></head>
<body><main>${inner}</main>
<script>
document.querySelectorAll("button[data-copy]").forEach(function (b) {
  b.addEventListener("click", function () {
    var text = document.getElementById(b.getAttribute("data-copy")).textContent;
    var done = function () { b.textContent = "已复制"; };
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, function () {});
  });
});
</script></body></html>`;
}
