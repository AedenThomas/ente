import { base64ToBytes } from "./utils";
import { TokenManager } from "../auth/token";

export interface AuthenticatorKey {
  encryptedKey: string;
  header: string;
  createdAt: number;
}

export async function decryptAuthenticatorData(encryptedData: string): Promise<string> {
  try {
    const tokenManager = new TokenManager();
    const masterKey = await tokenManager.getMasterKey();
    if (!masterKey) {
      throw new Error("No master key found for decryption");
    }

    const encryptedBytes = base64ToBytes(encryptedData);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: encryptedBytes.slice(0, 12), // First 12 bytes are the IV
      },
      await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["decrypt"]),
      encryptedBytes.slice(12) // Rest is the encrypted data
    );
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error("Failed to decrypt authenticator data:", error);
    throw new Error("Failed to decrypt authenticator data");
  }
}
