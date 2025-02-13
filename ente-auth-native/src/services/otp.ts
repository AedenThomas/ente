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
  let currentOTP: string;
  let nextOTP: string;

  switch (code.type) {
    case "totp": {
      const totp = new TOTP({
        secret: code.secret,
        algorithm: code.algorithm,
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
        secret: code.secret,
        counter: counter,
        algorithm: code.algorithm,
      });
      currentOTP = hotp.generate({ counter });
      nextOTP = hotp.generate({ counter: counter + 1 });
      break;
    }

    case "steam": {
      const steam = new Steam({ secret: code.secret });
      currentOTP = steam.generate();
      nextOTP = steam.generate({
        timestamp: Date.now() + code.period * 1000,
      });
      break;
    }

    default:
      throw new Error(`Unsupported OTP type: ${code.type}`);
  }

  return [currentOTP, nextOTP];
}
