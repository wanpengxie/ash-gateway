/** Routing metadata only. Payloads and execution state stay at the endpoints. */
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
    this.sql.exec("DELETE FROM device_tunnels WHERE kind = 'http' AND expires <= ?", Date.now());
    return this.sql.exec<TunnelRow>("SELECT * FROM device_tunnels WHERE sid = ?", sid).toArray()[0];
  }
  private remove(sid: string): void { this.sql.exec("DELETE FROM device_tunnels WHERE sid = ?", sid); }
  private finish(row: TunnelRow, code: number, reason: string): void {
    this.remove(row.sid);
    const frame = row.kind === "ws" ? { t: "tun", op: "ws.close", sid: row.sid, code, reason }
      : { t: "tun", op: "http.error", sid: row.sid, message: reason };
    this.owner({ ...frame, from: row.device });
    this.device(row.device, row.kind === "ws" ? frame : { t: "tun", op: "http.abort", sid: row.sid });
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
    const ws = op.startsWith("ws.");
    const fail = (reason: string) => this.owner(ws
      ? { t: "tun", op: "ws.close", sid, from: to, code: 4404, reason }
      : { t: "tun", op: "http.error", sid, from: to, message: reason });
    if (!sid || sid.length > 128) return fail("invalid sid");
    if (!this.available(to)) return fail("device_offline_or_forbidden");
    let row = this.row(sid);
    if (op === "ws.open" || op === "http.req") {
      if (row) return fail("sid already in use");
      if (ws && (!/^o-[A-Za-z0-9_-]{20,}$/.test(sid) || frame.path !== "/ash/device/stream")) return fail("invalid stream");
      if (ws) {
        for (const previous of this.sql.exec<TunnelRow>("SELECT * FROM device_tunnels WHERE device = ? AND kind = 'ws'", to).toArray())
          this.finish(previous, 4409, "replaced");
      }
      this.sql.exec("INSERT INTO device_tunnels (sid,device,kind,expires) VALUES (?,?,?,?)", sid, to, ws ? "ws" : "http", Date.now() + 180_000);
      row = { sid, device: to, kind: ws ? "ws" : "http", expires: Date.now() + 180_000 };
    }
    if (!row || row.device !== to || row.kind !== (ws ? "ws" : "http")) return fail("unknown stream");
    if (!(ws ? ["ws.open", "ws.msg", "ws.close"] : ["http.req", "http.reqbody", "http.reqend", "http.abort"]).includes(op)) return fail("invalid operation");
    if (op === "ws.msg" && !validChunk(frame)) { this.finish(row, 4400, "invalid or oversized chunk"); return; }
    this.device(to, { ...frame, from: ownerId });
    if (op === "ws.close" || op === "http.abort") this.remove(sid);
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
    if (!(row.kind === "ws" ? ["ws.opened", "ws.msg", "ws.close"] : ["http.head", "http.body", "http.end", "http.error"]).includes(op)) return;
    if (op === "ws.msg" && !validChunk(frame)) { this.finish(row, 4400, "invalid or oversized chunk"); return; }
    this.owner({ ...frame, from: deviceId, to: undefined });
    if (["ws.close", "http.end", "http.error"].includes(op)) this.remove(sid);
  }
}
function validChunk(frame: Frame): boolean {
  const text = typeof frame.text === "string", binary = typeof frame.b64 === "string";
  return text !== binary && new TextEncoder().encode(String(text ? frame.text : frame.b64)).length <= 256 * 1024;
}
