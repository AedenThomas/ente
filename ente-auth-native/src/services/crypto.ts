import { TokenManager } from "../auth/token";
import { decryptBox } from "../utils/crypto";

export interface AuthenticatorKey {
  encryptedKey: string;
  header: string;
  createdAt: number;
}

export async function decryptAuthenticatorData(encryptedData: string): Promise<string> {
  console.debug("[decryptAuthenticatorData] Received encryptedData (truncated):", encryptedData.substring(0, 20) + "...");
  const tokenManager = new TokenManager();
  const masterKey = await tokenManager.getMasterKey();
  if (!masterKey) {
    throw new Error("Master key not found");
  }
  console.debug("[decryptAuthenticatorData] Master key (bytes):", {
    length: masterKey.length,
    snippet: Array.from(masterKey.slice(0, 5)),
  });

  try {
    const encryptedBytes = Buffer.from(encryptedData, "base64");
    console.debug("[decryptAuthenticatorData] Encrypted data converted to bytes, length:", encryptedBytes.length);

    const decryptedBytes = await decryptBox(encryptedBytes, masterKey);
    const decryptedText = Buffer.from(decryptedBytes).toString("utf-8");
    console.debug("[decryptAuthenticatorData] Decrypted text (first 50 chars):", decryptedText.substring(0, 50));
    return decryptedText;
  } catch (error) {
    console.error("[decryptAuthenticatorData] Failed to decrypt data:", error);
    throw new Error("Failed to decrypt authenticator data");
  }
}
