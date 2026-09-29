// The only page the gateway itself serves: pair this browser with the phone and log in.
//
// The browser keeps a non-extractable P-256 key in IndexedDB. Pairing uses the one-time
// code shown on the phone; the phone approves (and grants `web_ui`); afterwards every
// visit signs a challenge to get a session cookie, and the phone's ash UI loads through
// the tunnel at "/".

export function webLoginPage(status = 200): Response {
  const state = status === 403 ? "forbidden" : status === 503 ? "offline" : "login";
  return new Response(PAGE.replace("__STATE__", state), {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
    },
  });
}

const PAGE = `<!doctype html>
<html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/icon.svg" type="image/svg+xml">
<title>Ash</title>
<style>
body{font:15px/1.6 system-ui,-apple-system,sans-serif;margin:0;background:#f6f7f9;color:#1d2430}
main{max-width:26rem;margin:12vh auto;padding:2rem;background:#fff;border-radius:14px;box-shadow:0 2px 16px #0001}
h1{font-size:1.4rem;margin:0 0 .3rem}p{margin:.4rem 0;color:#4a5566}
label{display:block;margin-top:1rem;font-size:.85rem;color:#4a5566}
input{width:100%;box-sizing:border-box;padding:.6rem .7rem;font-size:1rem;border:1px solid #ccd3dd;border-radius:8px;margin-top:.3rem}
button{margin-top:1.2rem;width:100%;padding:.7rem;font-size:1rem;border:0;border-radius:8px;background:#3d63f5;color:#fff;cursor:pointer}
button:disabled{background:#9aa9e8}
code{font-size:1.05rem;background:#eef1f6;padding:.1rem .4rem;border-radius:5px;letter-spacing:.04em}
.err{color:#c0392b}.muted{font-size:.85rem;color:#7a8595}
</style></head>
<body><main>
<h1>Ash</h1>
<div id="view"><p>正在连接…</p></div>
</main>
<script>
const STATE = "__STATE__";
const $ = (h) => { document.getElementById("view").innerHTML = h; };
const enc = (s) => new TextEncoder().encode(s);
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/") + "===".slice((s.length+3)%4)), c => c.charCodeAt(0));
const signingInput = (purpose, fields) => enc(["ash-gw/1", purpose, ...fields].join("\\n"));
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

function db() {
  return new Promise((res, rej) => {
    const r = indexedDB.open("ash-gateway", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("keys");
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function idb(mode, fn) {
  const d = await db();
  return new Promise((res, rej) => { const t = d.transaction("keys", mode); const q = fn(t.objectStore("keys")); t.oncomplete = () => res(q && q.result); t.onerror = () => rej(t.error); });
}
async function deviceId(spki) { return b64u(await crypto.subtle.digest("SHA-256", unb64u(spki))).slice(0, 22); }
async function fingerprint(spki) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", unb64u(spki))).slice(0, 8);
  return [...h].map(b => b.toString(16).padStart(2,"0")).join("").match(/.{4}/g).join("-").toUpperCase();
}
async function loadKey() { return idb("readonly", (s) => s.get("device")); }
async function newKey() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const spki = b64u(await crypto.subtle.exportKey("spki", pair.publicKey));
  const rec = { privateKey: pair.privateKey, spki, id: await deviceId(spki) };
  await idb("readwrite", (s) => s.put(rec, "device"));
  return rec;
}
async function sign(key, data) { return b64u(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, data)); }
async function api(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}), credentials: "same-origin" });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(j.message || j.error || r.status); e.code = j.error; throw e; }
  return j;
}

async function login(key) {
  const { nonce } = await api("/v1/auth/challenge", { device_id: key.id });
  await api("/v1/auth/session", { device_id: key.id, nonce, sig: await sign(key, signingInput("auth", [location.origin, key.id, nonce])) });
  location.replace("/");
}

function pairForm(msg) {
  $((msg ? '<p class="err">' + esc(msg) + '</p>' : '') +
    '<p>这个浏览器还没有和你的 Ash 手机配对。</p>' +
    '<p class="muted">在手机上打开 Ash 的「添加设备」，生成配对码，然后粘贴到下面。</p>' +
    '<label>配对码<input id="ticket" autocomplete="off" spellcheck="false"></label>' +
    '<label>设备名称<input id="name" value="浏览器 · ' + esc(navigator.platform || "web") + '"></label>' +
    '<button id="go">申请配对</button>');
  document.getElementById("go").onclick = pair;
}

async function pair() {
  const ticket = document.getElementById("ticket").value.trim();
  const name = document.getElementById("name").value.trim() || "浏览器";
  if (!ticket) return;
  document.getElementById("go").disabled = true;
  try {
    const key = (await loadKey()) || (await newKey());
    const r = await api("/v1/pair/request", { ticket, pubkey: key.spki, name });
    $('<p>请在手机上确认这个设备：</p>' +
      '<p>本设备指纹 <code>' + esc(await fingerprint(key.spki)) + '</code></p>' +
      '<p>手机指纹 <code>' + esc(r.owner_fingerprint) + '</code><br><span class="muted">应与手机上显示的一致</span></p>' +
      '<p class="muted" id="wait">等待手机确认…</p>');
    for (;;) {
      await new Promise((ok) => setTimeout(ok, 1500));
      const s = await api("/v1/pair/status", { request_id: r.request_id });
      if (s.status === "rejected") return pairForm("手机拒绝了这次配对。");
      if (s.status === "approved") {
        const ownerKey = await crypto.subtle.importKey("spki", unb64u(r.owner_key), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
        const perms = [...s.permissions].sort().join(",");
        const ok = s.owner_key === r.owner_key && await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, ownerKey, unb64u(s.approval_sig),
          signingInput("pair-approve", [location.origin, r.request_id, key.id, key.spki, perms, String(s.grant_version)]));
        if (!ok) return pairForm("批准签名校验失败，已停止。");
        if (!s.permissions.includes("web_ui")) return $('<p>已配对，但手机没有授予网页端权限（web_ui）。</p>');
        return login(key);
      }
    }
  } catch (e) {
    pairForm(e.code === "ticket_invalid" ? "配对码无效或已过期。" : e.code === "ticket_used" ? "这个配对码已经用过了。" : "配对失败：" + e.message);
  }
}

(async () => {
  if (STATE === "offline") return $('<p>手机现在不在线。</p><p class="muted">Ash 需要在手机上运行并连着网络。</p><button onclick="location.reload()">重试</button>');
  if (STATE === "forbidden") return $('<p>这个设备已配对，但没有网页端权限（web_ui）。</p><p class="muted">在手机上撤销后重新配对，并勾选网页端。</p>');
  const key = await loadKey();
  if (!key) return pairForm();
  try { await login(key); } catch (e) { pairForm(e.code === "unknown_device" ? "" : "登录失败：" + e.message); }
})();
</script></body></html>`;
