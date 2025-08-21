import { hash } from "argon2-wasm";
import * as sodium from "sodium-javascript";

// --- Crypto Constants (matching libsodium/Go implementation) ---
const SECRETBOX_MACBYTES = sodium.crypto_secretbox_MACBYTES;
const SECRETSTREAM_ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
const SECRETBOX_NONCEBYTES = sodium.crypto_secretbox_NONCEBYTES;
const HCHACHA20_INPUTBYTES = sodium.crypto_core_hchacha20_INPUTBYTES; // Correct constant
const HCHACHA20_OUTPUTBYTES = sodium.crypto_core_hchacha20_OUTPUTBYTES;

// --- Debugging Helpers ---
const logBuffer = (name: string, buf: Buffer | undefined, showContent = false) => {
  if (!buf) {
    console.log(`DEBUG: ${name} is undefined or null.`);
    return;
  }
  const length = buf.length;
  const content = showContent ? `(content: ${buf.toString("base64")})` : "";
  console.log(`DEBUG: ${name} (length: ${length}, type: Buffer) ${content}`);
};

// --- Crypto Helpers ---
function base64ToBuf(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}

function bufToBase64(buf: Buffer): string {
  return buf.toString("base64");
}

// --- LOGIN CRYPTOGRAPHIC CHAIN ---

export async function deriveKeyEncryptionKey(
  password: string,
  saltB64: string,
  memLimit: number,
  opsLimit: number,
): Promise<Buffer> {
  console.log("DEBUG: --- [Step 1] Starting Key Encryption Key (KEK) Derivation ---");
  const saltBuf = base64ToBuf(saltB64);
  logBuffer("Password Buffer", Buffer.from(password));
  logBuffer("Salt Buffer", saltBuf, true);
  console.log(`DEBUG: Argon2 Params -> memLimit (KiB): ${memLimit / 1024}, opsLimit (iterations): ${opsLimit}`);

  const result = await hash({
    pass: password,
    salt: saltBuf,
    time: opsLimit,
    mem: memLimit / 1024,
    hashLen: 32,
    parallelism: 1,
    type: 2, // Argon2id
  });

  const key = Buffer.from(result.hash);
  logBuffer("Derived KEK", key, true);
  console.log("DEBUG: --- [Step 1] Finished KEK Derivation ---");
  return key;
}

export function decryptMasterKey(encryptedKeyB64: string, nonceB64: string, keyEncryptionKey: Buffer): Buffer {
  console.log("DEBUG: --- [Step 2] Starting Master Key (MK) Decryption ---");
  const ciphertext = base64ToBuf(encryptedKeyB64);
  const nonce = base64ToBuf(nonceB64);

  logBuffer("Encrypted MK Ciphertext", ciphertext);
  logBuffer("MK Nonce", nonce, true);
  logBuffer("Using KEK for decryption", keyEncryptionKey, true);

  const decryptedMessage = Buffer.alloc(ciphertext.length - SECRETBOX_MACBYTES);

  if (!sodium.crypto_secretbox_open_easy(decryptedMessage, ciphertext, nonce, keyEncryptionKey)) {
    throw new Error("Failed to decrypt master key. This usually means the password is incorrect.");
  }

  logBuffer("Decrypted MK", decryptedMessage, true);
  console.log("DEBUG: --- [Step 2] Finished MK Decryption ---");
  return decryptedMessage;
}

export function decryptSecretKey(encryptedSecretKeyB64: string, nonceB64: string, masterKey: Buffer): Buffer {
  console.log("DEBUG: --- [Step 3] Starting Secret Key (SK) Decryption ---");
  const ciphertext = base64ToBuf(encryptedSecretKeyB64);
  const nonce = base64ToBuf(nonceB64);

  logBuffer("Encrypted SK Ciphertext", ciphertext);
  logBuffer("SK Nonce", nonce, true);
  logBuffer("Using MK for decryption", masterKey, true);

  const decryptedMessage = Buffer.alloc(ciphertext.length - SECRETBOX_MACBYTES);

  if (!sodium.crypto_secretbox_open_easy(decryptedMessage, ciphertext, nonce, masterKey)) {
    throw new Error("Failed to decrypt secret key.");
  }

  logBuffer("Decrypted SK", decryptedMessage, true);
  console.log("DEBUG: --- [Step 3] Finished SK Decryption ---");
  return decryptedMessage;
}

export function decryptSessionToken(encryptedTokenB64: string, nonceB64: string, masterKey: Buffer): string {
  console.log("DEBUG: --- [Step 4] Starting Session Token Decryption (using secretstream) ---");
  
  const ciphertext = base64ToBuf(encryptedTokenB64);
  const header = base64ToBuf(nonceB64);

  logBuffer("Token Ciphertext (from API)", ciphertext);
  logBuffer("Token Header/Nonce (from keyAttributes)", header, true);
  logBuffer("Using Master Key to derive subkey", masterKey, true);

  const subKey = Buffer.alloc(HCHACHA20_OUTPUTBYTES);
  const hchachaNonce = header.slice(0, HCHACHA20_INPUTBYTES);
  sodium.crypto_core_hchacha20(subKey, hchachaNonce, masterKey, null);
  logBuffer("Derived Stream Subkey", subKey, true);
  
  const state = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES);
  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, subKey);

  const decrypted = Buffer.alloc(ciphertext.length - SECRETSTREAM_ABYTES);
  const tag = Buffer.alloc(1);

  const success = sodium.crypto_secretstream_xchacha20poly1305_pull(state, decrypted, tag, ciphertext, null);

  if (!success) {
      console.error("DEBUG: [Step 4] Stream pull FAILED.");
      throw new Error('Failed to decrypt session token. MAC could not be verified.');
  }
  console.log("DEBUG: [Step 4] Stream pull SUCCEEDED.");

  const token = decrypted.toString('utf-8');
  console.log("DEBUG: SUCCESS! Decrypted Session Token:", token);
  console.log("DEBUG: --- [Step 4] Finished Session Token Decryption ---");
  return token;
}

// --- AUTHENTICATOR DATA CRYPTOGRAPHY ---

export function decryptAuthKey(encryptedKeyB64: string, headerB64: string, masterKey: Buffer): Buffer {
  console.log("DEBUG: --- Starting Auth Key Decryption (decryptAuthKey) ---");
  const ciphertext = base64ToBuf(encryptedKeyB64);
  const nonce = base64ToBuf(headerB64);
  logBuffer("Encrypted Auth Key Ciphertext", ciphertext);
  logBuffer("Auth Key Nonce", nonce, true);
  logBuffer("Using Master Key", masterKey, true);

  const decryptedMessage = Buffer.alloc(ciphertext.length - SECRETBOX_MACBYTES);
  
  if (!sodium.crypto_secretbox_open_easy(decryptedMessage, ciphertext, nonce, masterKey)) {
    throw new Error('Failed to decrypt authenticator key.');
  }

  logBuffer("Decrypted Auth Key", decryptedMessage, true);
  console.log("DEBUG: --- Finished Auth Key Decryption ---");
  return decryptedMessage;
}

export function decryptAuthEntity(encryptedDataB64: string, headerB64: string, authenticatorKey: Buffer): string {
  const header = base64ToBuf(headerB64);
  const subKey = Buffer.alloc(HCHACHA20_OUTPUTBYTES);
  const hchachaNonce = header.slice(0, HCHACHA20_INPUTBYTES);
  sodium.crypto_core_hchacha20(subKey, hchachaNonce, authenticatorKey, null);

  const state = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES);
  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, subKey);

  const ciphertext = base64ToBuf(encryptedDataB64);
  const decrypted = Buffer.alloc(ciphertext.length - SECRETSTREAM_ABYTES);
  const tag = Buffer.alloc(1);

  if (!sodium.crypto_secretstream_xchacha20poly1305_pull(state, decrypted, tag, ciphertext, null)) {
    throw new Error("Failed to decrypt authenticator entity.");
  }

  return decrypted.toString('utf-8');
}

export function encryptAuthKey(authenticatorKey: Buffer, masterKey: Buffer): { encryptedKeyB64: string; headerB64: string } {
    console.log("DEBUG: --- Starting Auth Key Encryption (encryptAuthKey) ---");
    const nonce = Buffer.alloc(SECRETBOX_NONCEBYTES);
    sodium.randombytes_buf(nonce);

    const ciphertext = Buffer.alloc(authenticatorKey.length + SECRETBOX_MACBYTES);
    sodium.crypto_secretbox_easy(ciphertext, authenticatorKey, nonce, masterKey);
    
    logBuffer("Generated Nonce (Header)", nonce, true);
    logBuffer("Encrypted Auth Key", ciphertext);
    console.log("DEBUG: --- Finished Auth Key Encryption ---");

    return {
        encryptedKeyB64: bufToBase64(ciphertext),
        headerB64: bufToBase64(nonce)
    };
}

export function generateAuthenticatorKey(): Buffer {
    const key = Buffer.alloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    sodium.randombytes_buf(key);
    logBuffer("Generated New Authenticator Key", key, true);
    return key;
}

export { base64ToBuf, bufToBase64 };