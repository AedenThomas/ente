import { hash } from 'argon2-wasm';
// Corrected import style for CommonJS compatibility
import * as sodium from 'sodium-javascript';

// --- Crypto Constants (matching libsodium/Go implementation) ---
const SECRETBOX_MACBYTES = 16;
const SECRETSTREAM_ABYTES = 17;
const SECRETBOX_NONCEBYTES = 24;


// --- Debugging Helpers ---
const logBuffer = (name: string, buf: Uint8Array | Buffer | undefined, showContent = false) => {
    if (!buf) {
        console.log(`DEBUG: ${name} is undefined or null.`);
        return;
    }
    const type = buf.constructor.name;
    const length = buf.length;
    const content = showContent ? `(content: ${Buffer.from(buf).toString('base64')})` : '';
    console.log(`DEBUG: ${name} (length: ${length}, type: ${type}) ${content}`);
};

// --- Crypto Helpers ---
function base64ToBuf(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function bufToBase64(buf: Uint8Array | Buffer): string {
  return Buffer.from(buf).toString('base64');
}

// --- LOGIN CRYPTOGRAPHIC CHAIN ---

/**
 * [Step 1] Derives the Key Encryption Key from the user's password using Argon2id.
 */
export async function deriveKeyEncryptionKey(password: string, saltB64: string, memLimit: number, opsLimit: number): Promise<Uint8Array> {
  console.log("DEBUG: --- [Step 1] Starting Key Encryption Key (KEK) Derivation ---");
  const saltBuf = base64ToBuf(saltB64);
  logBuffer("Password Buffer", Buffer.from(password));
  logBuffer("Salt Buffer", saltBuf);
  console.log(`DEBUG: Argon2 Params -> memLimit (KiB): ${memLimit / 1024}, opsLimit (iterations): ${opsLimit}`);

  const key = await hash({
    pass: password,
    salt: saltBuf,
    time: opsLimit,
    mem: memLimit / 1024,
    hashLen: 32,
    parallelism: 1,
    type: 2, // Argon2id
  });

  logBuffer("Derived KEK", key.hash, true);
  console.log("DEBUG: --- [Step 1] Finished KEK Derivation ---");
  return key.hash;
}

/**
 * [Step 2] Decrypts the Master Key using the Key Encryption Key.
 * This is a 'secretbox' operation.
 */
export function decryptMasterKey(encryptedKeyB64: string, nonceB64: string, keyEncryptionKey: Uint8Array): Uint8Array {
  console.log("DEBUG: --- [Step 2] Starting Master Key (MK) Decryption ---");
  const ciphertext = base64ToBuf(encryptedKeyB64);
  const nonce = base64ToBuf(nonceB64);
  
  logBuffer("Encrypted MK Ciphertext", ciphertext);
  logBuffer("MK Nonce", nonce);
  logBuffer("Using KEK for decryption", keyEncryptionKey, true);

  const decryptedMessage = Buffer.alloc(ciphertext.length - SECRETBOX_MACBYTES);

  if (!sodium.crypto_secretbox_open_easy(decryptedMessage, ciphertext, nonce, keyEncryptionKey)) {
    throw new Error('Failed to decrypt master key. This usually means the password is incorrect.');
  }
  
  logBuffer("Decrypted MK", decryptedMessage, true);
  console.log("DEBUG: --- [Step 2] Finished MK Decryption ---");
  return decryptedMessage;
}

/**
 * [Step 3] Decrypts the Secret Key using the Master Key.
 * This is also a 'secretbox' operation.
 */
export function decryptSecretKey(encryptedSecretKeyB64: string, nonceB64: string, masterKey: Uint8Array): Uint8Array {
    console.log("DEBUG: --- [Step 3] Starting Secret Key (SK) Decryption ---");
    const ciphertext = base64ToBuf(encryptedSecretKeyB64);
    const nonce = base64ToBuf(nonceB64);

    logBuffer("Encrypted SK Ciphertext", ciphertext);
    logBuffer("SK Nonce", nonce);
    logBuffer("Using MK for decryption", masterKey, true);
    
    const decryptedMessage = Buffer.alloc(ciphertext.length - SECRETBOX_MACBYTES);

    if (!sodium.crypto_secretbox_open_easy(decryptedMessage, ciphertext, nonce, masterKey)) {
        throw new Error('Failed to decrypt secret key.');
    }

    logBuffer("Decrypted SK", decryptedMessage, true);
    console.log("DEBUG: --- [Step 3] Finished SK Decryption ---");
    return decryptedMessage;
}


/**
 * [Step 4] Decrypts the session token using the SECRET KEY.
 * This is a 'secretstream' operation where the nonce is provided separately.
 */
export function decryptSessionToken(encryptedTokenB64: string, nonceB64: string, secretKey: Uint8Array): string {
  console.log("DEBUG: --- [Step 4] Starting Session Token Decryption ---");
  
  const ciphertext = base64ToBuf(encryptedTokenB64);
  const header = base64ToBuf(nonceB64); // The nonce is the header for the stream

  logBuffer("Token Ciphertext (from API)", ciphertext);
  logBuffer("Token Header (from keyAttributes)", header);
  logBuffer("Using SK for decryption", secretKey, true);
  
  const state = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES);
  console.log("DEBUG: [Step 4.1] Initializing pull stream...");
  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, secretKey);
  console.log("DEBUG: [Step 4.2] Pull stream initialized.");

  const decrypted = Buffer.alloc(ciphertext.length - SECRETSTREAM_ABYTES);
  const tag = Buffer.alloc(1);

  console.log("DEBUG: [Step 4.3] Pulling from stream...");
  const success = sodium.crypto_secretstream_xchacha20poly1305_pull(state, decrypted, tag, ciphertext, null);

  if (!success) {
      console.error("DEBUG: [Step 4.4] Stream pull FAILED.");
      throw new Error('Failed to decrypt session token. MAC could not be verified.');
  }
  console.log("DEBUG: [Step 4.4] Stream pull SUCCEEDED.");

  const token = decrypted.toString('utf-8');
  console.log("DEBUG: SUCCESS! Decrypted Session Token:", token);
  console.log("DEBUG: --- [Step 4] Finished Session Token Decryption ---");
  return token;
}

// --- AUTHENTICATOR DATA CRYPTOGRAPHY ---
// ... (rest of the file is correct and remains unchanged) ...
export function decryptAuthKey(encryptedKeyB64: string, headerB64: string, masterKey: Uint8Array): Uint8Array {
  console.log("DEBUG: --- Starting Auth Key Decryption (decryptAuthKey) ---");
  const ciphertext = base64ToBuf(encryptedKeyB64);
  const nonce = base64ToBuf(headerB64);
  logBuffer("Encrypted Auth Key Ciphertext", ciphertext);
  logBuffer("Auth Key Nonce", nonce);
  logBuffer("Using Master Key", masterKey, true);

  const decryptedMessage = Buffer.alloc(ciphertext.length - SECRETBOX_MACBYTES);
  
  if (!sodium.crypto_secretbox_open_easy(decryptedMessage, ciphertext, nonce, masterKey)) {
    throw new Error('Failed to decrypt authenticator key.');
  }

  logBuffer("Decrypted Auth Key", decryptedMessage, true);
  console.log("DEBUG: --- Finished Auth Key Decryption ---");
  return decryptedMessage;
}

export function decryptAuthEntity(encryptedDataB64: string, headerB64: string, authenticatorKey: Uint8Array): string {
  const state = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES);
  const header = base64ToBuf(headerB64);
  
  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, authenticatorKey);

  const ciphertext = base64ToBuf(encryptedDataB64);
  const decrypted = Buffer.alloc(ciphertext.length - SECRETSTREAM_ABYTES);
  const tag = Buffer.alloc(1);

  if (!sodium.crypto_secretstream_xchacha20poly1305_pull(state, decrypted, tag, ciphertext, null)) {
    throw new Error("Failed to decrypt authenticator entity.");
  }

  return decrypted.toString('utf-8');
}

export function encryptAuthKey(authenticatorKey: Uint8Array, masterKey: Uint8Array): { encryptedKeyB64: string; headerB64: string } {
    console.log("DEBUG: --- Starting Auth Key Encryption (encryptAuthKey) ---");
    const nonce = Buffer.alloc(SECRETBOX_NONCEBYTES);
    sodium.randombytes_buf(nonce);

    const ciphertext = Buffer.alloc(authenticatorKey.length + SECRETBOX_MACBYTES);
    sodium.crypto_secretbox_easy(ciphertext, authenticatorKey, nonce, masterKey);
    
    logBuffer("Generated Nonce (Header)", nonce);
    logBuffer("Encrypted Auth Key", ciphertext);
    console.log("DEBUG: --- Finished Auth Key Encryption ---");

    return {
        encryptedKeyB64: bufToBase64(ciphertext),
        headerB64: bufToBase64(nonce)
    };
}

export function generateAuthenticatorKey(): Uint8Array {
    const key = Buffer.alloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    sodium.randombytes_buf(key);
    logBuffer("Generated New Authenticator Key", key, true);
    return key;
}

export { base64ToBuf, bufToBase64 };