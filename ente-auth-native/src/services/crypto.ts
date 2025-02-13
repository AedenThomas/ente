import { base64ToBytes } from "./utils";

export interface AuthenticatorKey {
  encryptedKey: string;
  keyDecryptionNonce: string;
  publicKey: string;
  encryptedSecretKey: string;
  secretKeyDecryptionNonce: string;
  memLimit: number;
  opsLimit: number;
}

export async function decryptAuthenticatorData(encryptedData: string, key?: Uint8Array): Promise<string> {
  if (!key) {
    throw new Error("No key provided for decryption");
  }

  try {
    const encryptedBytes = base64ToBytes(encryptedData);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: encryptedBytes.slice(0, 12), // First 12 bytes are the IV
      },
      await crypto.subtle.importKey(
        "raw",
        key,
        "AES-GCM",
        false,
        ["decrypt"]
      ),
      encryptedBytes.slice(12) // Rest is the encrypted data
    );
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("Failed to decrypt authenticator data:", error);
    throw new Error("Failed to decrypt authenticator data");
  }
} 