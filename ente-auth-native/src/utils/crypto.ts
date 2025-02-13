import { argon2id } from "hash-wasm";
import { Buffer } from "buffer";
import crypto from "crypto";

export async function deriveArgonKey(
  password: string,
  salt: string,
  memLimit: number,
  opsLimit: number,
): Promise<Uint8Array> {
  try {
    // Convert memLimit from bytes to KB as required by hash-wasm
    const memLimitKB = Math.floor(memLimit / 1024);

    console.log("Starting Argon2 key derivation with params:", {
      memLimitKB,
      opsLimit,
      saltLength: salt.length,
    });

    const saltBuffer = Buffer.from(salt, "base64");
    console.log("Salt buffer created, length:", saltBuffer.length);

    const hash = await argon2id({
      password,
      salt: saltBuffer,
      parallelism: 1,
      iterations: opsLimit,
      memorySize: memLimitKB, // Use KB instead of bytes
      hashLength: 32,
      outputType: "binary",
    });
    console.log("Argon2 key derived successfully, hash length:", hash.length);

    return new Uint8Array(hash);
  } catch (error) {
    console.error("Argon2 key derivation failed:", error);
    throw error;
  }
}

export async function deriveLoginKey(keyEncKey: Uint8Array): Promise<Uint8Array> {
  try {
    console.log("Starting login key derivation, keyEncKey length:", keyEncKey.length);

    const data = Buffer.from("login");
    console.log("Login data encoded");

    const hmac = crypto.createHmac("sha256", Buffer.from(keyEncKey));
    const signature = hmac.update(data).digest();
    console.log("HMAC signature generated, length:", signature.length);

    return new Uint8Array(signature);
  } catch (error) {
    console.error("Login key derivation failed:", error);
    throw error;
  }
}

export async function decryptToken(encryptedToken: string, keyEncKey: Uint8Array, nonce: string): Promise<string> {
  try {
    console.log("Starting token decryption");
    const nonceBuffer = Buffer.from(nonce, "base64");
    const encryptedBuffer = Buffer.from(encryptedToken, "base64");
    console.log("Buffers created:", {
      nonceLength: nonceBuffer.length,
      encryptedLength: encryptedBuffer.length,
    });

    const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(keyEncKey), nonceBuffer);

    const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
    console.log("Token decrypted successfully");

    return decrypted.toString("utf8");
  } catch (error) {
    console.error("Token decryption failed:", error);
    throw error;
  }
}

export function generateRandomBytes(length: number): Uint8Array {
  console.log("Generating random bytes, length:", length);
  return new Uint8Array(crypto.randomBytes(length));
}

export async function generateKeyPair(): Promise<{ publicKey: Buffer; privateKey: Buffer }> {
  try {
    console.log("Generating ECDH key pair");
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();

    const keyPair = {
      publicKey: ecdh.getPublicKey(),
      privateKey: ecdh.getPrivateKey(),
    };
    console.log("Key pair generated successfully");
    return keyPair;
  } catch (error) {
    console.error("Key pair generation failed:", error);
    throw error;
  }
}

export async function exportPublicKey(key: Buffer): Promise<string> {
  try {
    console.log("Exporting public key");
    const base64 = key.toString("base64");
    console.log("Public key exported successfully");
    return base64;
  } catch (error) {
    console.error("Public key export failed:", error);
    throw error;
  }
}

export async function importPublicKey(publicKeyBase64: string): Promise<Buffer> {
  try {
    console.log("Importing public key");
    const key = Buffer.from(publicKeyBase64, "base64");
    console.log("Public key imported successfully");
    return key;
  } catch (error) {
    console.error("Public key import failed:", error);
    throw error;
  }
}
