import { createHmac } from "crypto";

interface SteamOptions {
  secret: string;
  timestamp?: number;
}

export class Steam {
  private readonly secret: string;

  constructor(options: SteamOptions) {
    this.secret = options.secret;
  }

  generate(options: { timestamp?: number } = {}): string {
    const timestamp = Math.floor((options.timestamp ?? Date.now()) / 1000);
    const buffer = Buffer.alloc(8);
    buffer.writeInt32BE(0, 0);
    buffer.writeInt32BE(Math.floor(timestamp / 30), 4);

    const hmac = createHmac("sha1", Buffer.from(this.secret, "utf8"));
    const hash = hmac.update(buffer).digest();

    const start = hash[19] & 0xf;
    let code =
      ((hash[start] & 0x7f) << 24) |
      ((hash[start + 1] & 0xff) << 16) |
      ((hash[start + 2] & 0xff) << 8) |
      (hash[start + 3] & 0xff);

    code = code % 100000;
    return code.toString().padStart(5, "0");
  }
}
