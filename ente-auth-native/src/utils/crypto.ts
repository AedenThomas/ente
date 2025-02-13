import { argon2id } from "hash-wasm";
import { Buffer } from "buffer";
import crypto from "crypto";
import { KeyAttributes } from "../types/auth";
import { sodium } from "./sodium";
import { base64ToBytes, bytesToBase64 } from "./base64";

export async function deriveArgonKey(
  password: string,
  salt: string,
  memLimit: number,
  opsLimit: number
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
    console.log("Starting login key derivation");
    await sodium.init();
    return sodium.crypto_kdf_derive_from_key(
      32, // Length of the derived key (changed from 16 to 32)
      1, // Subkey ID
      "loginctx", // Context
      keyEncKey // Master key
    );
  } catch (error) {
    console.error("Login key derivation failed:", error);
    throw error;
  }
}

export async function decryptToken(keyAttributes: KeyAttributes, keyEncKey: Uint8Array): Promise<string> {
  try {
    console.log("Starting token decryption process");
    console.log("Key attributes:", {
      encryptedKey: keyAttributes.encryptedKey,
      keyDecryptionNonce: keyAttributes.keyDecryptionNonce,
      encryptedSecretKey: keyAttributes.encryptedSecretKey,
      secretKeyDecryptionNonce: keyAttributes.secretKeyDecryptionNonce,
      publicKey: keyAttributes.publicKey,
      encryptedToken: keyAttributes.encryptedToken,
    });
    console.log("Key encryption key length:", keyEncKey.length);

    // First decrypt the master key using key encryption key (KEK)
    const masterKey = await decryptMasterKey(keyAttributes, keyEncKey);
    console.log("Master key decrypted successfully, length:", masterKey.length);

    // Then decrypt the secret key using master key
    const secretKey = await decryptSecretKey(keyAttributes, masterKey);
    console.log("Secret key decrypted successfully, length:", secretKey.length);

    // Finally decrypt the token using secret key and public key
    const token = await decryptTokenWithSecretKey(keyAttributes.encryptedToken, keyAttributes.publicKey, secretKey);
    console.log("Token decrypted successfully, length:", token.length);

    return token;
  } catch (error) {
    console.error("Token decryption failed:", error);
    throw error;
  }
}

async function decryptMasterKey(keyAttributes: KeyAttributes, keyEncKey: Uint8Array): Promise<Uint8Array> {
  try {
    const encryptedKey = base64ToBytes(keyAttributes.encryptedKey);
    const nonce = base64ToBytes(keyAttributes.keyDecryptionNonce);
    console.log("Decrypting master key:", {
      encryptedKeyLength: encryptedKey.length,
      nonceLength: nonce.length,
      keyEncKeyLength: keyEncKey.length,
    });

    return sodium.crypto_secretbox_open_easy(encryptedKey, nonce, keyEncKey);
  } catch (error) {
    console.error("Failed to decrypt master key:", error);
    throw error;
  }
}

async function decryptSecretKey(keyAttributes: KeyAttributes, masterKey: Uint8Array): Promise<Uint8Array> {
  try {
    const encryptedSecretKey = base64ToBytes(keyAttributes.encryptedSecretKey);
    const nonce = base64ToBytes(keyAttributes.secretKeyDecryptionNonce);
    console.log("Decrypting secret key:", {
      encryptedSecretKeyLength: encryptedSecretKey.length,
      nonceLength: nonce.length,
      masterKeyLength: masterKey.length,
    });

    return sodium.crypto_secretbox_open_easy(encryptedSecretKey, nonce, masterKey);
  } catch (error) {
    console.error("Failed to decrypt secret key:", error);
    throw error;
  }
}

async function decryptTokenWithSecretKey(
  encryptedToken: string,
  publicKey: string,
  secretKey: Uint8Array
): Promise<string> {
  try {
    const encryptedTokenBytes = base64ToBytes(encryptedToken);
    const publicKeyBytes = base64ToBytes(publicKey);
    const decryptedToken = await sodium.crypto_box_seal_open(encryptedTokenBytes, publicKeyBytes, secretKey);
    return Buffer.from(decryptedToken).toString("utf8");
  } catch (error) {
    console.error("Failed to decrypt token:", error);
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
