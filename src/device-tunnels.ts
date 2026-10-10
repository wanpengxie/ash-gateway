import { LINK_PATH } from "./protocol";
/** Routing metadata only. Payloads and execution state stay at the endpoints. `kind` is always "ws" (column kept for existing stores). */
export interface TunnelRow { sid: string; device: string; kind: string; expires: number; [key: string]: string | number }
export interface TunnelSql {
  exec<T extends Record<string, SqlStorageValue>>(query: string, ...bindings: (string | number)[]): { toArray(): T[] };
}
type Frame = Record<string, unknown>;
export class DeviceTunnels {
  constructor(private sql: TunnelSql, private owner: (f: Frame) => void,
    private device: (id: string, f: Frame) => void, private available: (id: string) => boolean) {
    sql.exec("CREATE TABLE IF NOT EXISTS device_tunnels (sid TEXT PRIMARY KEY, device TEXT NOT NULL, kind TEXT NOT NULL, expires INTEGER NOT NULL)");
  }
  private row(sid: string): TunnelRow | undefined {
    return this.sql.exec<TunnelRow>("SELECT * FROM device_tunnels WHERE sid = ?", sid).toArray()[0];
  }
  private remove(sid: string): void { this.sql.exec("DELETE FROM device_tunnels WHERE sid = ?", sid); }
  private finish(row: TunnelRow, code: number, reason: string): void {
    this.remove(row.sid);
    const frame = { t: "tun", op: "ws.close", sid: row.sid, code, reason };
    this.owner({ ...frame, from: row.device });
    this.device(row.device, frame);
  }
  disconnect(device?: string, code = 4410, reason = "peer disconnected"): void {
    const rows = device ? this.sql.exec<TunnelRow>("SELECT * FROM device_tunnels WHERE device = ?", device).toArray()
      : this.sql.exec<TunnelRow>("SELECT * FROM device_tunnels").toArray();
    for (const row of rows) this.finish(row, code, reason);
  }
  fromOwner(frame: Frame, ownerId: string): void {
    const sid = typeof frame.sid === "string" ? frame.sid : "";
    const to = typeof frame.to === "string" ? frame.to : "";
    const op = String(frame.op);
    const fail = (reason: string) => this.owner(op.startsWith("http.")
      ? { t: "tun", op: "http.error", sid, from: to, message: reason }
      : { t: "tun", op: "ws.close", sid, from: to, code: 4404, reason });
    // Device HTTP tunnels were removed: every http.* op is refused, nothing is registered or forwarded.
    if (op.startsWith("http.")) return fail("http_tunnel_removed");
    if (!sid || sid.length > 128) return fail("invalid sid");
    if (!this.available(to)) return fail("device_offline_or_forbidden");
    let row = this.row(sid);
    if (op === "ws.open") {
      if (row) return fail("sid already in use");
      if (!/^o-[A-Za-z0-9_-]{20,}$/.test(sid)) return fail("invalid stream");
      if (frame.path !== LINK_PATH) return fail("path_not_allowed");
      for (const previous of this.sql.exec<TunnelRow>("SELECT * FROM device_tunnels WHERE device = ? AND kind = 'ws'", to).toArray())
        this.finish(previous, 4409, "replaced");
      this.sql.exec("INSERT INTO device_tunnels (sid,device,kind,expires) VALUES (?,?,?,?)", sid, to, "ws", Date.now() + 180_000);
      row = { sid, device: to, kind: "ws", expires: Date.now() + 180_000 };
    }
    if (!row || row.device !== to) return fail("unknown stream");
    if (!["ws.open", "ws.msg", "ws.close"].includes(op)) return fail("invalid operation");
    if (op === "ws.msg" && !validChunk(frame)) { this.finish(row, 4400, "invalid or oversized chunk"); return; }
    this.device(to, { ...frame, from: ownerId });
    if (op === "ws.close") this.remove(sid);
  }
  fromDevice(frame: Frame, deviceId: string): void {
    const sid = typeof frame.sid === "string" ? frame.sid : "";
    const op = String(frame.op);
    const row = this.row(sid);
    if (!row || row.device !== deviceId) {
      this.device(deviceId, op.startsWith("ws.") ? { t: "tun", op: "ws.close", sid, code: 4403, reason: "unknown stream" }
        : { t: "gw", op: "error", code: "forbidden", message: "unknown stream" });
      return;
    }
    if (!["ws.opened", "ws.msg", "ws.close"].includes(op)) return;
    if (op === "ws.msg" && !validChunk(frame)) { this.finish(row, 4400, "invalid or oversized chunk"); return; }
    this.owner({ ...frame, from: deviceId, to: undefined });
    if (op === "ws.close") this.remove(sid);
  }
}
function validChunk(frame: Frame): boolean {
  const text = typeof frame.text === "string", binary = typeof frame.b64 === "string";
  return text !== binary && new TextEncoder().encode(String(text ? frame.text : frame.b64)).length <= 256 * 1024;
}
