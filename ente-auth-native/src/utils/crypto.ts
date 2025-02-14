import { Buffer } from "buffer";
import * as crypto from "crypto";
import { KeyAttributes } from "../types/auth";
import { sodium } from "./sodium";
import { argon2id } from "hash-wasm";

/**
 * Converts a base64 string to a Uint8Array
 */
export function base64ToBytes(base64: string, isUrlSafe = false): Uint8Array {
  try {
    // Add detailed input validation logging
    console.debug("[base64ToBytes] Input validation:", {
      inputLength: base64.length,
      isUrlSafe,
      firstChars: base64.substring(0, 10),
      lastChars: base64.substring(base64.length - 10),
      containsPlus: base64.includes("+"),
      containsSlash: base64.includes("/"),
      containsUnderscore: base64.includes("_"),
      containsDash: base64.includes("-"),
      containsEquals: base64.includes("="),
      paddingLength: (base64.match(/=+$/)?.[0] || "").length,
      rawInput: base64,
    });

    let processedBase64 = base64;

    // Handle URL-safe conversion
    if (isUrlSafe) {
      // Convert URL-safe characters to standard base64
      processedBase64 = processedBase64.replace(/-/g, "+").replace(/_/g, "/");

      // Add padding if needed
      const paddingLength = (4 - (processedBase64.length % 4)) % 4;
      if (paddingLength > 0) {
        processedBase64 += "=".repeat(paddingLength);
      }
    }

    // Log the processed base64 before conversion
    console.debug("[base64ToBytes] Pre-conversion state:", {
      originalLength: base64.length,
      processedLength: processedBase64.length,
      addedPadding: processedBase64.length - base64.length,
      processedFirstChars: processedBase64.substring(0, 10),
      processedLastChars: processedBase64.substring(processedBase64.length - 10),
      containsUrlSafeChars: processedBase64.includes("-") || processedBase64.includes("_"),
      processedBase64: processedBase64,
    });

    const buffer = Buffer.from(processedBase64, "base64");

    // Validate output
    console.debug("[base64ToBytes] Conversion result:", {
      outputLength: buffer.length,
      firstBytes: Array.from(buffer.slice(0, 5)),
      expectedLength: Math.floor((base64.length * 3) / 4),
      actualLength: buffer.length,
      bufferBase64: buffer.toString("base64"),
    });

    return buffer;
  } catch (error) {
    console.error("[base64ToBytes] Conversion failed:", {
      error: error instanceof Error ? error.message : "Unknown error",
      stack: error instanceof Error ? error.stack : undefined,
      inputLength: base64.length,
      isUrlSafe,
      inputPreview: base64.substring(0, 20),
      rawInput: base64,
    });
    throw error;
  }
}

/**
 * Converts a Uint8Array to a base64 string
 */
export function bytesToBase64(bytes: Uint8Array, urlSafe = false): string {
  try {
    // Input validation
    console.debug("[bytesToBase64] Input validation:", {
      inputLength: bytes.length,
      urlSafe,
      firstBytes: Array.from(bytes.slice(0, 5)),
      isUint8Array: bytes instanceof Uint8Array,
    });

    // First convert to standard base64
    let base64 = Buffer.from(bytes).toString("base64");

    // Log intermediate state
    console.debug("[bytesToBase64] Standard base64:", {
      standardLength: base64.length,
      firstChars: base64.substring(0, 10),
      lastChars: base64.substring(base64.length - 10),
      containsPadding: base64.includes("="),
      paddingLength: (base64.match(/=+$/)?.[0] || "").length,
      rawBase64: base64,
    });

    if (urlSafe) {
      // Convert to URL-safe format and remove padding
      base64 = base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

      // Validate URL-safe conversion
      if (base64.includes("+") || base64.includes("/") || base64.includes("=")) {
        console.error("[bytesToBase64] URL-safe conversion failed - invalid characters present:", {
          base64: base64,
          containsPlus: base64.includes("+"),
          containsSlash: base64.includes("/"),
          containsEquals: base64.includes("="),
        });
        throw new Error("URL-safe conversion failed");
      }
    }

    // Log final output
    console.debug("[bytesToBase64] Final output:", {
      outputLength: base64.length,
      firstChars: base64.substring(0, 10),
      lastChars: base64.substring(base64.length - 10),
      isUrlSafe: urlSafe,
      format: {
        containsPlus: base64.includes("+"),
        containsSlash: base64.includes("/"),
        containsUnderscore: base64.includes("_"),
        containsDash: base64.includes("-"),
        containsEquals: base64.includes("="),
      },
      rawOutput: base64,
    });

    return base64;
  } catch (error) {
    console.error("[bytesToBase64] Conversion failed:", {
      error: error instanceof Error ? error.message : "Unknown error",
      stack: error instanceof Error ? error.stack : undefined,
      bytesLength: bytes.length,
      urlSafe,
      firstBytes: Array.from(bytes.slice(0, 5)),
      rawBytes: bytes,
    });
    throw error;
  }
}

/**
 * Derives an Argon2 key from a password and salt
 */
export async function deriveArgonKey(
  password: string,
  salt: string,
  memLimit: number,
  opsLimit: number
): Promise<Uint8Array> {
  try {
    console.log("[deriveArgonKey] Starting Argon2 key derivation with params:", {
      memLimitKB: Math.floor(memLimit / 1024),
      opsLimit,
      saltLength: salt.length,
    });

    // Convert salt from base64
    const saltBuffer = base64ToBytes(salt);
    console.log("[deriveArgonKey] Salt buffer created, length:", saltBuffer.length);

    // Use argon2id from hash-wasm
    const hash = await argon2id({
      password: Buffer.from(password),
      salt: saltBuffer,
      parallelism: 1,
      iterations: opsLimit,
      memorySize: Math.floor(memLimit / 1024), // Convert to KB
      hashLength: 32,
      outputType: "binary",
    });

    console.log("[deriveArgonKey] Argon2 key derived successfully, hash length:", hash.length);
    return hash;
  } catch (error) {
    console.error("[deriveArgonKey] Failed to derive key:", {
      error: error instanceof Error ? error.message : "Unknown error",
      memLimit,
      opsLimit,
      saltLength: salt.length,
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw error;
  }
}

/**
 * Derives a login key from a key encryption key
 */
export async function deriveLoginKey(keyEncKey: Uint8Array): Promise<Uint8Array> {
  try {
    console.log("[deriveLoginKey] Starting login key derivation:", {
      keyEncKeyLength: keyEncKey.length,
      firstBytes: Array.from(keyEncKey.slice(0, 5)),
      keyEncKeyType: Object.prototype.toString.call(keyEncKey),
      isBuffer: keyEncKey instanceof Buffer,
      base64: Buffer.from(keyEncKey).toString("base64"),
    });

    await sodium.init();

    // Ensure key is the correct length
    if (keyEncKey.length !== 32) {
      throw new Error(`Invalid key length: ${keyEncKey.length}, expected 32`);
    }

    // Convert key to Buffer if needed
    const keyBuffer = keyEncKey instanceof Buffer ? keyEncKey : Buffer.from(keyEncKey);
    console.log("[deriveLoginKey] Key prepared:", {
      keyBufferLength: keyBuffer.length,
      keyBufferFirstBytes: Array.from(keyBuffer.slice(0, 5)),
      keyBufferType: Object.prototype.toString.call(keyBuffer),
      isBuffer: keyBuffer instanceof Buffer,
      base64: keyBuffer.toString("base64"),
      equals: Buffer.compare(keyBuffer, Buffer.from(keyEncKey)) === 0,
    });

    // Derive the subkey
    const subKey = await sodium.crypto_kdf_derive_from_key(16, 1, "loginctx", keyBuffer);
    console.log("[deriveLoginKey] Subkey derived:", {
      subKeyLength: subKey.length,
      subKeyFirstBytes: Array.from(subKey.slice(0, 5)),
      subKeyType: Object.prototype.toString.call(subKey),
      isBuffer: subKey instanceof Buffer,
      base64: Buffer.from(subKey).toString("base64"),
    });

    return subKey;
  } catch (error) {
    console.error("[deriveLoginKey] Failed to derive login key:", {
      error: error instanceof Error ? error.message : "Unknown error",
      stack: error instanceof Error ? error.stack : undefined,
      keyEncKeyLength: keyEncKey.length,
      keyEncKeyType: Object.prototype.toString.call(keyEncKey),
    });
    throw error;
  }
}

/**
 * Decrypts data using the master key
 */
export async function decryptBox(encryptedData: Uint8Array, masterKey: Uint8Array): Promise<Uint8Array> {
  try {
    console.log("[decryptBox] Starting decryption with data length:", encryptedData.length);
    await sodium.init();

    // Get nonce bytes length and split data
    const nonceBytes = await sodium.crypto_secretbox_NONCEBYTES();
    console.log("[decryptBox] Expected nonce length:", nonceBytes);

    if (encryptedData.length < nonceBytes) {
      throw new Error(
        `Encrypted data too short: ${encryptedData.length} bytes, need at least ${nonceBytes} bytes for nonce`
      );
    }

    const nonce = encryptedData.slice(0, nonceBytes);
    const ciphertext = encryptedData.slice(nonceBytes);

    console.log("[decryptBox] Decryption parameters:", {
      nonceLength: nonce.length,
      ciphertextLength: ciphertext.length,
      masterKeyLength: masterKey.length,
      nonceFirstBytes: Array.from(nonce.slice(0, 5)),
      ciphertextFirstBytes: Array.from(ciphertext.slice(0, 5)),
      nonceExpectedLength: nonceBytes,
      masterKeyExpectedLength: 32, // libsodium secretbox key length
      nonceBase64: bytesToBase64(nonce),
      ciphertextBase64Prefix: bytesToBase64(ciphertext.slice(0, 32)),
    });

    if (masterKey.length !== 32) {
      throw new Error(`Invalid master key length: ${masterKey.length} bytes, expected 32 bytes`);
    }

    if (nonce.length !== nonceBytes) {
      throw new Error(`Invalid nonce length: ${nonce.length} bytes, expected ${nonceBytes} bytes`);
    }

    if (ciphertext.length < 16) {
      // Minimum size for the MAC
      throw new Error(`Ciphertext too short: ${ciphertext.length} bytes, need at least 16 bytes for MAC`);
    }

    const decrypted = await sodium.crypto_secretbox_open_easy(ciphertext, nonce, masterKey);

    console.log("[decryptBox] Decryption successful:", {
      decryptedLength: decrypted.length,
      decryptedFirstBytes: Array.from(decrypted.slice(0, 5)),
      decryptedBase64Prefix: bytesToBase64(decrypted.slice(0, 32)),
      isValidUTF8: isValidUTF8(decrypted),
    });

    return decrypted;
  } catch (error) {
    console.error("[decryptBox] Decryption failed:", {
      error: error instanceof Error ? error.message : "Unknown error",
      stack: error instanceof Error ? error.stack : undefined,
      dataLength: encryptedData.length,
      masterKeyLength: masterKey.length,
      masterKeyBase64: bytesToBase64(masterKey),
    });
    throw new Error("Failed to decrypt data: " + (error instanceof Error ? error.message : "Unknown error"));
  }
}

/**
 * Decrypts a token using key attributes and master key
 */
export async function decryptToken(
  keyAttributes: KeyAttributes & { encryptedToken: string },
  keyEncKey: Uint8Array
): Promise<Uint8Array> {
  // Add detailed input validation logging
  console.debug("[decryptToken] Starting token decryption:", {
    encryptedTokenLength: keyAttributes.encryptedToken.length,
    encryptedTokenFormat: {
      containsPlus: keyAttributes.encryptedToken.includes("+"),
      containsSlash: keyAttributes.encryptedToken.includes("/"),
      containsUnderscore: keyAttributes.encryptedToken.includes("_"),
      containsDash: keyAttributes.encryptedToken.includes("-"),
      containsEquals: keyAttributes.encryptedToken.includes("="),
      paddingLength: (keyAttributes.encryptedToken.match(/=+$/)?.[0] || "").length,
      rawToken: keyAttributes.encryptedToken,
    },
    keyEncKeyLength: keyEncKey.length,
    keyEncKeyFirstBytes: Array.from(keyEncKey.slice(0, 4)),
    keyAttrsKeys: Object.keys(keyAttributes),
  });

  // Validate required fields
  const requiredFields = [
    "encryptedToken",
    "encryptedKey",
    "keyDecryptionNonce",
    "encryptedSecretKey",
    "secretKeyDecryptionNonce",
    "publicKey",
  ] as const;

  const missingFields = requiredFields.filter((field) => {
    const key = field as keyof typeof keyAttributes;
    return !keyAttributes[key];
  });

  if (missingFields.length > 0) {
    throw new Error(`Missing required key attributes: ${missingFields.join(", ")}`);
  }

  try {
    // Step 1: Decrypt the master key
    console.debug("[decryptToken] Step 1 - Decrypting master key");
    console.debug("[decryptToken] Input for master key decryption:", {
      encryptedKey: keyAttributes.encryptedKey,
      keyDecryptionNonce: keyAttributes.keyDecryptionNonce,
      keyEncKeyLength: keyEncKey.length,
    });

    const encryptedKey = base64ToBytes(keyAttributes.encryptedKey);
    const keyDecryptionNonce = base64ToBytes(keyAttributes.keyDecryptionNonce);

    console.debug("[decryptToken] Converted base64 to bytes:", {
      encryptedKeyLength: encryptedKey.length,
      nonceLength: keyDecryptionNonce.length,
      encryptedKeyFirstBytes: Array.from(encryptedKey.slice(0, 4)),
      nonceFirstBytes: Array.from(keyDecryptionNonce.slice(0, 4)),
    });

    if (keyEncKey.length !== 32) {
      throw new Error(`Invalid key encryption key length: ${keyEncKey.length} bytes, expected 32`);
    }

    await sodium.init();
    const masterKey = await sodium.crypto_secretbox_open_easy(encryptedKey, keyDecryptionNonce, keyEncKey);

    console.debug("[decryptToken] Master key decrypted:", {
      masterKeyLength: masterKey.length,
      masterKeyFirstBytes: Array.from(masterKey.slice(0, 4)),
      expectedLength: 32,
    });

    if (masterKey.length !== 32) {
      throw new Error(`Invalid master key length: ${masterKey.length} bytes, expected 32`);
    }

    // Step 2: Decrypt the secret key
    console.debug("[decryptToken] Step 2 - Decrypting secret key");
    console.debug("[decryptToken] Input for secret key decryption:", {
      encryptedSecretKey: keyAttributes.encryptedSecretKey,
      secretKeyDecryptionNonce: keyAttributes.secretKeyDecryptionNonce,
      masterKeyLength: masterKey.length,
    });

    const encryptedSecretKey = base64ToBytes(keyAttributes.encryptedSecretKey);
    const secretKeyNonce = base64ToBytes(keyAttributes.secretKeyDecryptionNonce);

    console.debug("[decryptToken] Converted secret key base64 to bytes:", {
      encryptedSecretKeyLength: encryptedSecretKey.length,
      nonceLength: secretKeyNonce.length,
      encryptedSecretKeyFirstBytes: Array.from(encryptedSecretKey.slice(0, 4)),
      nonceFirstBytes: Array.from(secretKeyNonce.slice(0, 4)),
    });

    const secretKey = await sodium.crypto_secretbox_open_easy(encryptedSecretKey, secretKeyNonce, masterKey);

    console.debug("[decryptToken] Secret key decrypted:", {
      secretKeyLength: secretKey.length,
      secretKeyFirstBytes: Array.from(secretKey.slice(0, 4)),
      expectedLength: 32,
    });

    if (secretKey.length !== 32) {
      throw new Error(`Invalid secret key length: ${secretKey.length} bytes, expected 32`);
    }

    // Step 3: Decrypt the token
    console.debug("[decryptToken] Step 3 - Decrypting token");
    console.debug("[decryptToken] Input for token decryption:", {
      encryptedToken: keyAttributes.encryptedToken,
      publicKey: keyAttributes.publicKey,
      secretKeyLength: secretKey.length,
    });

    // Always treat encryptedToken as URL-safe base64
    const encryptedToken = base64ToBytes(keyAttributes.encryptedToken, true);
    const publicKey = base64ToBytes(keyAttributes.publicKey);

    console.debug("[decryptToken] Converted token and public key base64 to bytes:", {
      encryptedTokenLength: encryptedToken.length,
      publicKeyLength: publicKey.length,
      encryptedTokenFirstBytes: Array.from(encryptedToken.slice(0, 4)),
      publicKeyFirstBytes: Array.from(publicKey.slice(0, 4)),
    });

    if (publicKey.length !== 32) {
      throw new Error(`Invalid public key length: ${publicKey.length} bytes, expected 32`);
    }

    const decryptedToken = await sodium.crypto_box_seal_open(encryptedToken, publicKey, secretKey);

    console.debug("[decryptToken] Token decrypted:", {
      tokenLength: decryptedToken.length,
      tokenFirstBytes: Array.from(decryptedToken.slice(0, 4)),
      expectedLength: 32,
    });

    if (decryptedToken.length !== 32) {
      throw new Error(`Invalid decrypted token length: ${decryptedToken.length} bytes, expected 32`);
    }

    // Verify the final token format
    const tokenB64 = bytesToBase64(decryptedToken, true); // Always use URL-safe for final token
    console.debug("[decryptToken] Final token format:", {
      base64Length: tokenB64.length,
      base64Format: {
        containsPlus: tokenB64.includes("+"),
        containsSlash: tokenB64.includes("/"),
        containsUnderscore: tokenB64.includes("_"),
        containsDash: tokenB64.includes("-"),
        containsEquals: tokenB64.includes("="),
      },
      expectedLength: 43, // Standard length for URL-safe base64 of 32 bytes
      rawToken: tokenB64,
    });

    return decryptedToken;
  } catch (err) {
    const error = err as Error;
    console.error("[decryptToken] Token decryption failed:", {
      error: error.message || "Unknown error",
      stack: error.stack,
      phase: error.message?.includes("secretbox")
        ? "master_key_decryption"
        : error.message?.includes("box")
        ? "token_decryption"
        : "unknown",
      context: {
        encryptedTokenLength: keyAttributes.encryptedToken.length,
        keyEncKeyLength: keyEncKey.length,
        keyAttributesPresent: Object.keys(keyAttributes),
        rawError: err,
      },
    });
    throw error;
  }
}

/**
 * Checks if a Uint8Array contains valid UTF-8 text
 */
function isValidUTF8(bytes: Uint8Array): boolean {
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    decoder.decode(bytes);
    return true;
  } catch {
    return false;
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

/**
 * Pads a buffer to a specific length with zeros at the start
 * This is compatible with SRP6Util.getPadded from the mobile implementation
 */
export function padBuffer(buffer: Buffer, targetLength: number): Buffer {
  try {
    console.log("[padBuffer] Starting padding:", {
      inputLength: buffer.length,
      targetLength,
      firstBytes: Array.from(buffer.slice(0, 5)),
      base64: buffer.toString("base64"),
      isBuffer: buffer instanceof Buffer,
      type: Object.prototype.toString.call(buffer),
    });

    if (buffer.length >= targetLength) {
      console.log("[padBuffer] Buffer already at target length, returning as is");
      return buffer;
    }

    // Create a new buffer filled with zeros
    const padded = Buffer.alloc(targetLength, 0);
    console.log("[padBuffer] Created zero-filled buffer:", {
      paddedLength: padded.length,
      firstBytes: Array.from(padded.slice(0, 5)),
      isBuffer: padded instanceof Buffer,
      type: Object.prototype.toString.call(padded),
      base64: padded.toString("base64"),
    });

    // Copy the input buffer to the end of the padded buffer
    buffer.copy(padded, targetLength - buffer.length);

    console.log("[padBuffer] Padding complete:", {
      outputLength: padded.length,
      firstBytes: Array.from(padded.slice(0, 5)),
      base64: padded.toString("base64"),
      originalLength: buffer.length,
      equals: Buffer.compare(buffer.slice(-buffer.length), padded.slice(-buffer.length)) === 0,
      isBuffer: padded instanceof Buffer,
      type: Object.prototype.toString.call(padded),
      paddingLength: targetLength - buffer.length,
      lastBytesMatch: Buffer.compare(buffer.slice(-5), padded.slice(-5)) === 0,
      paddingBytes: Array.from(padded.slice(0, targetLength - buffer.length)),
    });

    // Verify the padding
    if (padded.length !== targetLength) {
      throw new Error(`Padding failed: output length ${padded.length} does not match target length ${targetLength}`);
    }

    // Verify the original data is preserved
    if (Buffer.compare(buffer, padded.slice(-buffer.length)) !== 0) {
      throw new Error("Padding failed: original data not preserved");
    }

    return padded;
  } catch (error) {
    console.error("[padBuffer] Failed to pad buffer:", {
      error: error instanceof Error ? error.message : "Unknown error",
      stack: error instanceof Error ? error.stack : undefined,
      inputLength: buffer.length,
      targetLength,
      isBuffer: buffer instanceof Buffer,
      type: Object.prototype.toString.call(buffer),
    });
    throw error;
  }
}
