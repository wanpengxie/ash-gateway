import { b64u, fromB64u } from "../src/protocol";
type Frame = Record<string, unknown>;
export interface StreamClose { code: number; reason: string }
/** One multiplexed, bounded stream. Reconnect/replay belongs to the application. */
export class DeviceStream {
  private messages = new Set<(message: string | Uint8Array) => void>();
  private closers = new Set<(result: StreamClose) => void>();
  private parts: string[] = [];
  private bytes = 0;
  private binary: boolean | null = null;
  private ended: StreamClose | null = null;
  constructor(readonly sid: string, readonly peer: string, readonly path: string,
    private transmit: (frame: Frame) => void, private remove: () => void) {}
  onMessage(handler: (message: string | Uint8Array) => void): () => void {
    this.messages.add(handler); return () => this.messages.delete(handler);
  }
  onClose(handler: (result: StreamClose) => void): () => void {
    if (this.ended) handler(this.ended); else this.closers.add(handler);
    return () => this.closers.delete(handler);
  }
  send(message: string | Uint8Array): void {
    if (this.ended) throw new Error("stream is closed");
    const binary = typeof message !== "string";
    if ((binary ? message.byteLength : new TextEncoder().encode(message).byteLength) > 4 * 1024 * 1024) throw new Error("stream message too large");
    const payload = binary ? b64u(new Uint8Array(message)) : message;
    for (let i = 0; i < payload.length || i === 0;) {
      let end = Math.min(payload.length, i + 60_000);
      if (end < payload.length && /[\uD800-\uDBFF]/.test(payload[end - 1])) end--;
      this.transmit({ t: "tun", op: "ws.msg", sid: this.sid, [binary ? "b64" : "text"]: payload.slice(i, end), more: end < payload.length });
      i = end;
      if (!payload.length) break;
    }
  }
  accept(frame: Frame): void {
    if (this.ended) return;
    if (frame.op === "ws.close") { this.finish({ code: Number(frame.code) || 1000, reason: String(frame.reason ?? "closed") }); return; }
    if (frame.op !== "ws.msg") return;
    const binary = typeof frame.b64 === "string";
    const chunk = binary ? frame.b64 : frame.text;
    if (typeof chunk !== "string" || (this.binary !== null && this.binary !== binary)) { this.close(4400, "invalid fragments"); return; }
    this.binary = binary;
    this.bytes += new TextEncoder().encode(chunk).byteLength;
    if (this.bytes > (binary ? 6 : 4) * 1024 * 1024 || this.parts.length >= 1024) { this.close(4400, "message too large"); return; }
    this.parts.push(chunk);
    if (frame.more === true) return;
    const payload = this.parts.join("");
    this.parts = []; this.bytes = 0; this.binary = null;
    let result: string | Uint8Array;
    try { result = binary ? fromB64u(payload) : payload; } catch { this.close(4400, "invalid binary"); return; }
    if (typeof result !== "string" && result.byteLength > 4 * 1024 * 1024) { this.close(4400, "message too large"); return; }
    for (const handler of this.messages) handler(result);
  }
  close(code = 1000, reason = "closed"): void {
    if (this.ended) return;
    try { this.transmit({ t: "tun", op: "ws.close", sid: this.sid, code, reason }); }
    finally { this.finish({ code, reason }); }
  }
  finish(result: StreamClose): void {
    if (this.ended) return;
    this.ended = result; this.parts = []; this.bytes = 0; this.remove();
    for (const handler of this.closers) handler(result);
    this.closers.clear(); this.messages.clear();
  }
}
