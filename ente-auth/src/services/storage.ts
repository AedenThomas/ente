import { LocalStorage } from "@raycast/api";
import { AuthData, AuthKey, UserCredentials } from "../types";
import { bufToBase64, base64ToBuf } from "./crypto";
import { pbkdf2Sync, randomBytes, createCipheriv, createDecipheriv } from "crypto";

// This salt is used *only* for deriving a key to encrypt local storage.
const STORAGE_SALT = "ente-raycast-local-storage-salt";
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export class StorageService {
  private masterKey: Uint8Array | null = null;
  private storageEncryptionKey: Buffer | null = null;

  private async getStorageEncryptionKey(): Promise<Buffer> {
    if (this.storageEncryptionKey) {
      return this.storageEncryptionKey;
    }

    const masterKey = await this.getMasterKey();
    if (!masterKey) throw new Error("Master key is not set. Cannot derive storage key.");

    // Use Node.js's built-in pbkdf2Sync for key derivation.
    this.storageEncryptionKey = pbkdf2Sync(
      masterKey,
      STORAGE_SALT,
      100000,
      32, // 256 bits for AES-256
      "sha256",
    );
    console.log("DEBUG: Derived local storage encryption key.");
    return this.storageEncryptionKey;
  }

  private async encryptData(data: string): Promise<string> {
    const key = await this.getStorageEncryptionKey();
    const iv = randomBytes(IV_LENGTH);

    const cipher = createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");

    const authTag = cipher.getAuthTag();

    // Combine iv, authTag, and encrypted data for storage
    return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
  }

  private async decryptData(encryptedString: string): Promise<string> {
    const key = await this.getStorageEncryptionKey();
    const parts = encryptedString.split(":");

    if (parts.length !== 3) {
      throw new Error("Invalid encrypted data format.");
    }

    const [ivHex, authTagHex, encryptedDataHex] = parts;

    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");

    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedDataHex, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }

  async getMasterKey(): Promise<Uint8Array | null> {
    if (this.masterKey) return this.masterKey;
    // getCredentials will set the master key in memory if successful
    const creds = await this.getCredentials();
    return creds ? creds.masterKey : null;
  }

  // This method is called by the login flow to prime the service
  setMasterKey(key: Uint8Array) {
    this.masterKey = key;
  }

  async storeCredentials(credentials: UserCredentials): Promise<void> {
    this.masterKey = credentials.masterKey; // Set master key in memory
    console.log("DEBUG: Master key set in memory for StorageService.");

    const storableCredentials = {
      ...credentials,
      masterKey: bufToBase64(credentials.masterKey), // Convert Uint8Array to Base64 for JSON
    };

    const encrypted = await this.encryptData(JSON.stringify(storableCredentials));
    await LocalStorage.setItem("credentials", encrypted);
    await LocalStorage.setItem("token", credentials.token);
    console.log("DEBUG: Credentials have been encrypted and stored.");
  }

  async getCredentials(): Promise<UserCredentials | null> {
    const encryptedData = (await LocalStorage.getItem("credentials")) as string | undefined;
    if (!encryptedData) return null;

    try {
      if (!this.masterKey) {
        // This is a critical security check. Without the master key from login, we cannot decrypt.
        console.warn("Attempted to get credentials without a master key in memory. This requires re-login.");
        return null;
      }

      const decrypted = await this.decryptData(encryptedData);
      const storedCreds = JSON.parse(decrypted);

      const credentials: UserCredentials = {
        ...storedCreds,
        masterKey: base64ToBuf(storedCreds.masterKey),
      };

      this.masterKey = credentials.masterKey; // Refresh cache
      return credentials;
    } catch (error) {
      console.error("Failed to decrypt credentials, clearing storage for security.", error);
      await this.clearAll();
      return null;
    }
  }

  async storeAuthKey(authKey: AuthKey): Promise<void> {
    const encrypted = await this.encryptData(JSON.stringify(authKey));
    await LocalStorage.setItem("authKey", encrypted);
  }

  async getAuthKey(): Promise<AuthKey | null> {
    const encryptedData = (await LocalStorage.getItem("authKey")) as string | undefined;
    if (!encryptedData) return null;
    try {
      const decrypted = await this.decryptData(encryptedData);
      return JSON.parse(decrypted);
    } catch (error) {
      console.error("Failed to decrypt auth key:", error);
      return null;
    }
  }

  async storeAuthEntities(entities: AuthData[]): Promise<void> {
    const encrypted = await this.encryptData(JSON.stringify(entities));
    await LocalStorage.setItem("authEntities", encrypted);
  }

  async getAuthEntities(): Promise<AuthData[]> {
    const encryptedData = (await LocalStorage.getItem("authEntities")) as string | undefined;
    if (!encryptedData) return [];
    try {
      const decrypted = await this.decryptData(encryptedData);
      return JSON.parse(decrypted);
    } catch (error) {
      console.error("Failed to decrypt auth entities:", error);
      return [];
    }
  }

  async storeLastSyncTime(time: number): Promise<void> {
    await LocalStorage.setItem("lastSyncTime", time.toString());
  }

  async getLastSyncTime(): Promise<number> {
    const time = (await LocalStorage.getItem("lastSyncTime")) as string | undefined;
    return time ? parseInt(time, 10) : 0;
  }

  async clearAll(): Promise<void> {
    this.masterKey = null;
    this.storageEncryptionKey = null;
    await LocalStorage.clear();
  }
}

let storageServiceInstance: StorageService | null = null;
export const getStorageService = (): StorageService => {
  if (!storageServiceInstance) {
    storageServiceInstance = new StorageService();
  }
  return storageServiceInstance;
};
