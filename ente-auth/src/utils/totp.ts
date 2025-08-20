import { Buffer } from "buffer";
import { HmacSHA1, HmacSHA256, HmacSHA512 } from "crypto-js";

// Steam alphabet for Steam Guard codes
const steamAlphabet = "23456789BCDFGHJKMNPQRTVWXY";

function base32Decode(secret: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let decoded = "";

  for (let i = 0; i < secret.length; i++) {
    const char = secret.charAt(i).toUpperCase();
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error("Invalid base32 character");
    }
    bits += index.toString(2).padStart(5, "0");
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    const chunk = bits.substr(i, 8);
    decoded += String.fromCharCode(parseInt(chunk, 2));
  }
  return Buffer.from(decoded, "binary");
}

function hmac(algorithm: string, key: Buffer, message: Buffer) {
  const keyWordArray = { words: [key.readInt32BE(0)], sigBytes: key.length };
  const msgWordArray = { words: [message.readInt32BE(0), message.readInt32BE(4)], sigBytes: message.length };

  let hash;
  switch (algorithm.toLowerCase()) {
    case "sha256":
      hash = HmacSHA256(msgWordArray, keyWordArray);
      break;
    case "sha512":
      hash = HmacSHA512(msgWordArray, keyWordArray);
      break;
    case "sha1":
    default:
      hash = HmacSHA1(msgWordArray, keyWordArray);
      break;
  }
  const buffer = Buffer.alloc(hash.sigBytes);
  for (let i = 0; i < hash.sigBytes / 4; i++) {
    buffer.writeInt32BE(hash.words[i], i * 4);
  }
  return buffer;
}

function generate(
  secret: string,
  counter: number,
  digits: number,
  algorithm: "sha1" | "sha256" | "sha512",
  type: "totp" | "hotp" | "steam",
): string {
  const key = base32Decode(secret.replace(/\s/g, ""));

  const counterBuffer = Buffer.alloc(8);
  let current = counter;
  for (let i = 7; i >= 0; i--) {
    counterBuffer[i] = current & 0xff;
    current >>= 8;
  }

  const hash = hmac(algorithm, key, counterBuffer);
  const offset = hash[hash.length - 1] & 0xf;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  if (type === "steam") {
    let code = "";
    let tempBinary = binary;
    for (let i = 0; i < digits; i++) {
      code += steamAlphabet.charAt(tempBinary % steamAlphabet.length);
      tempBinary = Math.floor(tempBinary / steamAlphabet.length);
    }
    return code;
  } else {
    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, "0");
  }
}

export const generateTOTP = (
  secret: string,
  period = 30,
  digits = 6,
  algorithm: "sha1" | "sha256" | "sha512" = "sha1",
  type: "totp" | "steam" = "totp",
): string => {
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / period);
  return generate(secret, counter, digits, algorithm, type);
};

export const getRemainingSeconds = (period = 30): number => {
  const now = Math.floor(Date.now() / 1000);
  return period - (now % period);
};

export const getProgress = (period = 30): number => {
  return (getRemainingSeconds(period) / period) * 100;
};
