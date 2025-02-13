import { decryptBoxB64 } from "./sodium";

export interface AuthenticatorKey {
  encryptedKey: string;
  keyDecryptionNonce: string;
}

export async function decryptAuthenticatorData(data: string, key?: Uint8Array): Promise<string> {
  if (!key) {
    throw new Error("No key provided for decryption");
  }

  try {
    const decrypted = await decryptBoxB64(data, key);
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("Failed to decrypt authenticator data:", error);
    throw new Error("Failed to decrypt authenticator data");
  }
} 