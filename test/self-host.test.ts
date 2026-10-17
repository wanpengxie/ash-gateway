import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, readlinkSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { buildBundle } from "../scripts/build-bundle";

const source = join(import.meta.dirname, "../scripts/self-host");
function script(path: string, body: string) { writeFileSync(path, body, { mode: 0o755 }); }
async function fixture(t: { after(fn: () => void): void }) {
  const dir = mkdtempSync(join(tmpdir(), "relay-upgrade-")); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const root = join(dir, "relay"), bin = join(dir, "bin"), units = join(dir, "units"), assets = join(dir, "assets");
  for (const d of [bin, units, join(root, "releases/0.7.1"), join(root, "node_modules/.bin")]) mkdirSync(d, { recursive: true });
  await buildBundle(assets);
  writeFileSync(join(root, ".dev.vars"), "BOOTSTRAP_SECRET=keep-this-local\n", { mode: 0o600 });
  writeFileSync(join(root, "state-sentinel"), "persistent owner and device data");
  writeFileSync(join(units, "ash-relay.service"), "[Service]\nExecStart=old-runtime\n");
  symlinkSync("releases/0.7.1", join(root, "current"));
  script(join(root, "node_modules/.bin/workerd"), "#!/bin/sh\nexit 0\n");
  script(join(bin, "sleep"), "#!/bin/sh\nexit 0\n");
  script(join(bin, "systemctl"), `#!/usr/bin/env node
const fs=require('node:fs'),p=require('node:path');
fs.appendFileSync(process.env.CALLS,process.argv.slice(2).join(' ')+'\\n');
if(process.env.FAIL_RESTART && process.argv[2]==='restart' && fs.readFileSync(p.join(process.env.ASH_RELAY_UNIT_DIR,'ash-relay.service'),'utf8').includes('workerd serve'))process.exit(1);
if(process.argv[2]==='is-active' && process.env.INACTIVE)process.exit(3);
`);
  script(join(bin, "curl"), `#!/usr/bin/env node
const fs=require('node:fs'),p=require('node:path'),a=process.argv.slice(2),out=a.indexOf('-o');
if(out>=0){fs.copyFileSync(p.join(process.env.ASSETS,a.at(-1).split('/').at(-1)),a[out+1]);process.exit(0);}
if(process.env.HEALTH_FAIL)process.exit(22);
const version=fs.readlinkSync(p.join(process.env.ASH_RELAY_ROOT,'current')).split('/').at(-1);
console.log(JSON.stringify({ok:true,version:process.env.FAIL_NEW && version!=='0.7.1'?'bad':version}));
`);
  const env = { ...process.env, PATH: bin + ":" + process.env.PATH, ASH_RELAY_ROOT: root, ASH_RELAY_UNIT_DIR: units, ASH_RELAY_RELEASES: "https://releases.example", ASSETS: assets, CALLS: join(dir, "calls") };
  return { root, units, assets, env };
}

test("production upgrades install one workerd and health guard without changing secrets or persistent data", async (t) => {
  const f = await fixture(t), version = JSON.parse(readFileSync(join(import.meta.dirname, "../package.json"), "utf8")).version;
  const r = spawnSync("sh", [join(source, "upgrade.sh"), version], { env: f.env, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr); assert.equal(readlinkSync(join(f.root, "current")), `releases/${version}`);
  assert.match(readFileSync(join(f.units, "ash-relay.service"), "utf8"), /\.bin\/workerd serve --experimental/);
  assert.doesNotMatch(readFileSync(join(f.units, "ash-relay.service"), "utf8"), /ExecStart=.*wrangler/);
  assert.match(readFileSync(f.env.CALLS, "utf8"), /enable --now ash-relay-health.timer/);
  assert.equal(readFileSync(join(f.root, ".dev.vars"), "utf8"), "BOOTSTRAP_SECRET=keep-this-local\n");
  assert.equal(readFileSync(join(f.root, "state-sentinel"), "utf8"), "persistent owner and device data");
});

for (const failure of ["FAIL_NEW", "FAIL_RESTART"]) test(`a ${failure} upgrade restores the previous files and systemd unit`, async (t) => {
  const f = await fixture(t), version = JSON.parse(readFileSync(join(import.meta.dirname, "../package.json"), "utf8")).version;
  const r = spawnSync("sh", [join(source, "upgrade.sh"), version], { env: { ...f.env, [failure]: "1" }, encoding: "utf8" });
  assert.equal(r.status, 1); assert.equal(readlinkSync(join(f.root, "current")), "releases/0.7.1");
  assert.equal(readFileSync(join(f.units, "ash-relay.service"), "utf8"), "[Service]\nExecStart=old-runtime\n");
  assert.equal(existsSync(join(f.units, "ash-relay-health.timer")), false);
  assert.equal(readFileSync(join(f.root, "state-sentinel"), "utf8"), "persistent owner and device data");
});

test("a corrupt download cannot switch or restart the relay", async (t) => {
  const f = await fixture(t); writeFileSync(join(f.assets, "workerd.capnp"), "corrupt");
  const r = spawnSync("sh", [join(source, "upgrade.sh"), "0.7.2"], { env: f.env, encoding: "utf8" });
  assert.equal(r.status, 1); assert.match(r.stderr, /checksum failed/);
  assert.equal(readlinkSync(join(f.root, "current")), "releases/0.7.1"); assert.equal(existsSync(f.env.CALLS), false);
});

test("health guard restarts a nonresponsive active unit, and leaves healthy or stopped units alone", async (t) => {
  const f = await fixture(t);
  for (const scenario of [{}, { INACTIVE: "1", HEALTH_FAIL: "1" }, { HEALTH_FAIL: "1" }]) {
    writeFileSync(f.env.CALLS, "");
    const r = spawnSync("sh", [join(source, "healthcheck.sh")], { env: { ...f.env, ...scenario }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(readFileSync(f.env.CALLS, "utf8").includes("restart ash-relay"), !!scenario.HEALTH_FAIL && !scenario.INACTIVE);
  }
});
