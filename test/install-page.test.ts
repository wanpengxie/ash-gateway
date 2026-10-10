import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_INSTALL_SCRIPT_URL, detectOs, installCommand, installPage, installScriptUrl } from "../src/install-page";

const origin = "https://relay.example.workers.dev";
const code = "AbCd1234_-AbCd1234_-AbCd";
const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15";
const WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";
const LINUX = "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0";

test("operating system comes from the user agent", () => {
  assert.equal(detectOs(MAC), "mac");
  assert.equal(detectOs(WIN), "windows");
  assert.equal(detectOs(LINUX), "linux");
  assert.equal(detectOs("Mozilla/5.0 (Linux; Android 14) Chrome"), "other");
  assert.equal(detectOs("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"), "other");
  assert.equal(detectOs(""), "other");
});

test("the command is one line with the gateway and the code; Windows has none", () => {
  const cmd = installCommand("mac", origin, code)!;
  assert.equal(cmd, `curl -fsSL '${DEFAULT_INSTALL_SCRIPT_URL}' | sh -s -- '${origin}' '${code}'`);
  assert.ok(!cmd.includes("\n"));
  assert.equal(installCommand("linux", origin, code), cmd);
  assert.equal(installCommand("windows", origin, code), null);
});

test("the page shows the command, marks the detected system, and is private", async () => {
  const res = installPage(origin, code, MAC);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  const html = await res.text();
  assert.ok(html.includes(`&#39;${origin}&#39; &#39;${code}&#39;`), "escaped command");
  assert.match(html, /<section data-os="mac" class="here">/);
  assert.ok(!html.includes('data-os="linux" class="here"'));
  assert.ok(html.includes("data-copy"), "copy button");
  const win = await installPage(origin, code, WIN).text();
  assert.match(win, /<section data-os="windows" class="here">/);
});

test("anything that is not a plain code is refused and never reaches the page", async () => {
  for (const bad of ["", "short", "x".repeat(129), "a b a b a b a b", "abcdefgh'; rm -rf ~; '", "<script>alert(1)<", "%27abcdefghij", "abcdefgh/../x"]) {
    const res = installPage(origin, bad, MAC);
    assert.equal(res.status, 404, bad);
    assert.ok(!(await res.text()).includes("rm -rf"), bad);
  }
  assert.equal(installPage("https://x'; id; '", code, MAC).status, 404);
});

test("the installer address comes from INSTALL_SCRIPT_URL, falling back to the default", async () => {
  const custom = "https://downloads.example.com/ash/install.sh";
  assert.equal(installScriptUrl(custom), custom);
  assert.equal(installScriptUrl(`  ${custom}\n`), custom);
  for (const bad of [undefined, "", "http://example.com/i.sh", "https://x.com/i.sh?a=1&b=2", "https://x.com/$(id)", "https://x.com/a b", "https://x.com/'; id; '", "javascript:alert(1)"])
    assert.equal(installScriptUrl(bad), DEFAULT_INSTALL_SCRIPT_URL, String(bad));
  const html = await installPage(origin, code, LINUX, custom).text();
  assert.ok(html.includes(`curl -fsSL &#39;${custom}&#39; |`));
  assert.ok(!html.includes(DEFAULT_INSTALL_SCRIPT_URL));
  assert.ok((await installPage(origin, code, LINUX, "https://x.com/$(id)").text()).includes(DEFAULT_INSTALL_SCRIPT_URL));
  assert.equal(installCommand("linux", origin, code, custom), `curl -fsSL '${custom}' | sh -s -- '${origin}' '${code}'`);
});

test("local debugging origins are accepted over plain http, other http origins are not", () => {
  assert.equal(installPage("http://127.0.0.1:8787", code, MAC).status, 200);
  assert.equal(installPage("http://localhost:8787", code, MAC).status, 200);
  assert.equal(installPage("http://relay.example.com", code, MAC).status, 404);
  assert.equal(installPage("http://127.0.0.1.evil.com", code, MAC).status, 404);
});

test("a pairing code starting with '-' stays a positional argument of the installer", async () => {
  const dashed = "-AbCd1234_-AbCd1234_-AbCd";
  const cmd = installCommand("linux", origin, dashed)!;
  assert.ok(cmd.includes(`-- '${origin}' '${dashed}'`), "after the -- separator");
  assert.equal(installPage(origin, dashed, LINUX).status, 200);
});
