function checksum(payload) {
  let value = 0;
  for (const byte of Buffer.from(payload, "ascii")) value = (value + byte) & 0xff;
  return value.toString(16).padStart(2, "0");
}
export class RspClient {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.waiters = [];
    socket.on("data", data => { this.buffer = Buffer.concat([this.buffer, data]); this.pump(); });
    socket.on("error", error => this.rejectAll(error));
    socket.on("close", () => this.rejectAll(new Error("GDB connection closed")));
  }
  rejectAll(error) { while (this.waiters.length) this.waiters.shift().reject(error); }
  pump() {
    for (;;) {
      while (this.buffer.length && (this.buffer[0] === 0x2b || this.buffer[0] === 0x2d)) this.buffer = this.buffer.subarray(1);
      const start = this.buffer.indexOf(0x24);
      if (start < 0) return;
      if (start) this.buffer = this.buffer.subarray(start);
      const hash = this.buffer.indexOf(0x23, 1);
      if (hash < 0 || this.buffer.length < hash + 3) return;
      const payload = this.buffer.subarray(1, hash).toString("ascii");
      const received = this.buffer.subarray(hash + 1, hash + 3).toString("ascii").toLowerCase();
      this.buffer = this.buffer.subarray(hash + 3);
      this.socket.write(received === checksum(payload) ? "+" : "-");
      if (received !== checksum(payload)) continue;
      const waiter = this.waiters.shift();
      if (waiter) waiter.resolve(payload);
    }
  }
  nextPacket(timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject };
      this.waiters.push(waiter);
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error(`GDB response timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      waiter.resolve = value => { clearTimeout(timer); resolve(value); };
      waiter.reject = error => { clearTimeout(timer); reject(error); };
      this.pump();
    });
  }
  async packet(payload, timeoutMs = 5000) {
    this.socket.write(`$${payload}#${checksum(payload)}`, "ascii");
    return await this.nextPacket(timeoutMs);
  }
  async halt() {
    const status = await this.packet("?", 5000);
    if (/^[STW]/.test(status)) return status;
    this.socket.write(Buffer.from([0x03]));
    const stop = await this.nextPacket(15000);
    if (!/^[STW]/.test(stop)) throw new Error(`unexpected stop reply: ${stop}`);
    return stop;
  }
  resume() {
    const payload = "c";
    this.socket.write(`$${payload}#${checksum(payload)}`, "ascii");
  }
  step() {
    const payload = "s";
    this.socket.write(`$${payload}#${checksum(payload)}`, "ascii");
  }
  close() { this.socket.destroy(); }
}
