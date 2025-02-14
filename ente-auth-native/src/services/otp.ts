import { TOTP, HOTP } from "otpauth";
import { Steam } from "./steam";

export interface Code {
  id: string;
  type: "totp" | "hotp" | "steam";
  account?: string;
  issuer: string;
  length: number;
  period: number;
  algorithm: "sha1" | "sha256" | "sha512";
  counter?: number;
  secret: string;
}

export function generateOTPs(code: Code): [string, string] {
  console.debug("[generateOTPs] Generating OTP for code:", {
    id: code.id,
    type: code.type,
    secretSnippet: code.secret.substring(0, 8) + "...",
  });
  let currentOTP: string;
  let nextOTP: string;

  // Ensure secret is properly formatted (remove spaces and convert to uppercase)
  const secret = code.secret.replace(/\s/g, "").toUpperCase();

  switch (code.type) {
    case "totp": {
      const totp = new TOTP({
        secret,
        algorithm: code.algorithm.toUpperCase(),
        period: code.period,
        digits: code.length,
      });
      currentOTP = totp.generate();
      nextOTP = totp.generate({
        timestamp: Date.now() + code.period * 1000,
      });
      break;
    }

    case "hotp": {
      const counter = code.counter ?? 0;
      const hotp = new HOTP({
        secret,
        algorithm: code.algorithm.toUpperCase(),
        digits: code.length,
      });
      currentOTP = hotp.generate({ counter });
      nextOTP = hotp.generate({ counter: counter + 1 });
      break;
    }

    case "steam": {
      const steam = new Steam({ secret });
      const now = Math.floor(Date.now() / 1000);
      currentOTP = steam.generate({ timestamp: now });
      nextOTP = steam.generate({
        timestamp: now + code.period,
      });
      break;
    }

    default:
      throw new Error(`Unsupported OTP type: ${code.type}`);
  }

  console.debug("[generateOTPs] OTPs generated:", { currentOTP, nextOTP });
  return [currentOTP, nextOTP];
}
