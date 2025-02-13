import { base64ToBytes } from "./utils";

export async function decryptBoxB64(encryptedData: string, key: Uint8Array): Promise<Uint8Array> {
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
    return new Uint8Array(decrypted);
  } catch (error) {
    console.error("Failed to decrypt data:", error);
    throw new Error("Failed to decrypt data");
  }
} 