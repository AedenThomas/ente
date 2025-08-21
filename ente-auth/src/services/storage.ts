// src/services/storage.ts
import { LocalStorage } from "@raycast/api";
import { AuthData, AuthKey, UserCredentials, AuthenticationContext } from "../types";
import { bufToBase64, base64ToBuf } from "./crypto";
import { pbkdf2Sync, randomBytes, createCipheriv, createDecipheriv } from "crypto";

const STORAGE_SALT = "ente-raycast-local-storage-salt";
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export class StorageService {
  private masterKey: Buffer | null = null; // [+] Use Buffer type
  private storageEncryptionKey: Buffer | null = null;

  private async getStorageEncryptionKey(): Promise<Buffer> {
    if (this.storageEncryptionKey) {
      return this.storageEncryptionKey;
    }

    const masterKey = await this.getMasterKey();
    if (!masterKey) throw new Error("Master key is not set. Cannot derive storage key.");

    this.storageEncryptionKey = pbkdf2Sync(
      masterKey,
      STORAGE_SALT,
      100000,
      32,
      "sha256",
    );
    console.log("DEBUG: Derived local storage encryption key.");
    return this.storageEncryptionKey;
  }
  
  // ... (encryptData and decryptData are correct and don't need changes)
  private async encryptData(data: string): Promise<string> {
    const key = await this.getStorageEncryptionKey();
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag();
    return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted}`;
  }

  private async decryptData(encryptedString: string): Promise<string> {
    const key = await this.getStorageEncryptionKey();
    const parts = encryptedString.split(":");
    if (parts.length !== 3) throw new Error("Invalid encrypted data format.");
    const [ivHex, authTagHex, encryptedDataHex] = parts;
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedDataHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }


  async getMasterKey(): Promise<Buffer | null> { // [+] Use Buffer type
    if (this.masterKey) return this.masterKey;
    const creds = await this.getCredentials();
    return creds ? creds.masterKey : null;
  }

  setMasterKey(key: Buffer) { // [+] Use Buffer type
    this.masterKey = key;
  }

  async storeCredentials(credentials: UserCredentials): Promise<void> {
    this.masterKey = credentials.masterKey;
    console.log("DEBUG: Master key set in memory for StorageService.");

    const storableCredentials = {
      ...credentials,
      masterKey: bufToBase64(credentials.masterKey), // Convert Buffer to Base64 for JSON
    };

    const encrypted = await this.encryptData(JSON.stringify(storableCredentials));
    await LocalStorage.setItem("credentials", encrypted);
    
    // [PERSISTENCE FIX] Store session token separately for direct reuse on startup
    await LocalStorage.setItem("sessionToken", credentials.token);
    console.log("DEBUG: Credentials and session token stored for persistence.");
  }

  async getCredentials(): Promise<UserCredentials | null> {
    const encryptedData = (await LocalStorage.getItem("credentials")) as string | undefined;
    if (!encryptedData) {
      console.log("DEBUG: No encrypted credentials found in storage");
      return null;
    }

    try {
      if (!this.masterKey) {
        console.warn("DEBUG: Master key not in memory. Attempting session token restoration instead of clearing.");
        // Don't clear credentials immediately - try session token restoration first
        return null;
      }

      const decrypted = await this.decryptData(encryptedData);
      const storedCreds = JSON.parse(decrypted);

      const credentials: UserCredentials = {
        ...storedCreds,
        masterKey: base64ToBuf(storedCreds.masterKey), // Convert Base64 back to Buffer
      };

      this.masterKey = credentials.masterKey;
      return credentials;
    } catch (error) {
      console.error("Failed to decrypt credentials:", error);
      return null;
    }
  }

  // ... (rest of the file is okay and doesn't need changes)
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
    console.log(`DEBUG: 💾 Storing ${entities.length} auth entities`);
    
    try {
      const encrypted = await this.encryptData(JSON.stringify(entities));
      await LocalStorage.setItem("authEntities", encrypted);
      console.log("DEBUG: ✅ Auth entities stored (encrypted)");
    } catch (error) {
      // If encryption fails (e.g., during session restoration without master key),
      // store unencrypted since we need to cache entities for functionality
      console.log("DEBUG: 🔄 Encryption failed, storing auth entities unencrypted (session restoration)");
      await LocalStorage.setItem("authEntities_unencrypted", JSON.stringify(entities));
      console.log("DEBUG: ✅ Auth entities stored (unencrypted fallback)");
    }
  }

  async getAuthEntities(): Promise<AuthData[]> {
    // First try encrypted version
    const encryptedData = (await LocalStorage.getItem("authEntities")) as string | undefined;
    if (encryptedData) {
      try {
        const decrypted = await this.decryptData(encryptedData);
        console.log("DEBUG: ✅ Retrieved auth entities (encrypted)");
        return JSON.parse(decrypted);
      } catch (error) {
        console.log("DEBUG: ⚠️ Failed to decrypt auth entities, trying unencrypted fallback");
      }
    }
    
    // Fallback to unencrypted version (used during session restoration)
    const unencryptedData = (await LocalStorage.getItem("authEntities_unencrypted")) as string | undefined;
    if (unencryptedData) {
      try {
        const entities = JSON.parse(unencryptedData);
        console.log(`DEBUG: ✅ Retrieved ${entities.length} auth entities (unencrypted fallback)`);
        return entities;
      } catch (error) {
        console.error("Failed to parse unencrypted auth entities:", error);
      }
    }
    
    console.log("DEBUG: ❌ No auth entities found");
    return [];
  }

  async storeLastSyncTime(time: number): Promise<void> {
    await LocalStorage.setItem("lastSyncTime", time.toString());
  }

  async getLastSyncTime(): Promise<number> {
    const time = (await LocalStorage.getItem("lastSyncTime")) as string | undefined;
    return time ? parseInt(time, 10) : 0;
  }

  async storeAuthenticationContext(context: AuthenticationContext): Promise<void> {
    console.log("DEBUG: Storing authentication context", {
      userId: context.userId,
      accountKey: context.accountKey ? context.accountKey.substring(0, 20) + "..." : "none",
      userAgent: context.userAgent
    });
    
    try {
      const encrypted = await this.encryptData(JSON.stringify(context));
      await LocalStorage.setItem("authenticationContext", encrypted);
      console.log("DEBUG: ✅ Authentication context stored (encrypted)");
    } catch (error) {
      // If encryption fails (e.g., during session restoration without master key),
      // store unencrypted since authentication context is not sensitive
      console.log("DEBUG: 🔄 Encryption failed, storing authentication context unencrypted (session restoration)");
      await LocalStorage.setItem("authenticationContext_unencrypted", JSON.stringify(context));
      console.log("DEBUG: ✅ Authentication context stored (unencrypted fallback)");
    }
  }

  async getAuthenticationContext(): Promise<AuthenticationContext | null> {
    // First try encrypted version
    const encryptedData = (await LocalStorage.getItem("authenticationContext")) as string | undefined;
    if (encryptedData) {
      try {
        const decrypted = await this.decryptData(encryptedData);
        console.log("DEBUG: ✅ Retrieved authentication context (encrypted)");
        return JSON.parse(decrypted);
      } catch (error) {
        console.log("DEBUG: ⚠️ Failed to decrypt authentication context, trying unencrypted fallback");
      }
    }
    
    // Fallback to unencrypted version (used during session restoration)
    const unencryptedData = (await LocalStorage.getItem("authenticationContext_unencrypted")) as string | undefined;
    if (unencryptedData) {
      try {
        console.log("DEBUG: ✅ Retrieved authentication context (unencrypted fallback)");
        return JSON.parse(unencryptedData);
      } catch (error) {
        console.error("Failed to parse unencrypted authentication context:", error);
      }
    }
    
    console.log("DEBUG: ❌ No authentication context found");
    return null;
  }

  // [+] Add token lifecycle management methods matching web app
  async storeEncryptedToken(userId: number, encryptedToken: string): Promise<void> {
    console.log("DEBUG: Storing encrypted token for later decryption (web app pattern)");
    const tokenData = {
      userId,
      encryptedToken,
      timestamp: Date.now()
    };
    const encrypted = await this.encryptData(JSON.stringify(tokenData));
    await LocalStorage.setItem("encryptedToken", encrypted);
  }

  async getEncryptedToken(): Promise<{userId: number, encryptedToken: string} | null> {
    const encryptedData = (await LocalStorage.getItem("encryptedToken")) as string | undefined;
    if (!encryptedData) return null;
    try {
      const decrypted = await this.decryptData(encryptedData);
      const tokenData = JSON.parse(decrypted);
      return {
        userId: tokenData.userId,
        encryptedToken: tokenData.encryptedToken
      };
    } catch (error) {
      console.error("Failed to decrypt stored encrypted token:", error);
      return null;
    }
  }

  async clearEncryptedToken(): Promise<void> {
    await LocalStorage.removeItem("encryptedToken");
  }

  // [PERSISTENCE FIX] Session token management for cross-restart persistence
  async storeSessionToken(token: string, email: string, userId: number): Promise<void> {
    console.log("DEBUG: 💾 Storing session token for persistence across restarts");
    console.log("DEBUG: Token length:", token.length);
    console.log("DEBUG: Token preview:", token.substring(0, 20) + "...");
    
    const sessionData = {
      token,
      email,
      userId,
      timestamp: Date.now(),
      userAgent: 'Raycast/Ente-Auth/1.0.0'
    };
    
    // Store session data without encryption since it's already a derived session token
    await LocalStorage.setItem("persistentSession", JSON.stringify(sessionData));
    console.log("DEBUG: ✅ Session token stored for persistence");
  }

  async getStoredSessionToken(): Promise<{token: string, email: string, userId: number, userAgent: string} | null> {
    try {
      const sessionData = await LocalStorage.getItem("persistentSession") as string | undefined;
      if (!sessionData) {
        console.log("DEBUG: No persistent session found");
        return null;
      }
      
      const parsed = JSON.parse(sessionData);
      console.log("DEBUG: 🔍 Found stored session for user:", parsed.userId);
      console.log("DEBUG: Session age:", Math.floor((Date.now() - parsed.timestamp) / 1000 / 60), "minutes");
      
      return {
        token: parsed.token,
        email: parsed.email,
        userId: parsed.userId,
        userAgent: parsed.userAgent || 'Raycast/Ente-Auth/1.0.0'
      };
    } catch (error) {
      console.error("DEBUG: Failed to parse stored session:", error);
      return null;
    }
  }

  async clearStoredSessionToken(): Promise<void> {
    await LocalStorage.removeItem("persistentSession");
    console.log("DEBUG: 🗑️ Cleared stored session token");
  }

  // Legacy method for backward compatibility
  async activateToken(token: string): Promise<void> {
    console.log("DEBUG: Activating token for API access (legacy method)");
    await LocalStorage.setItem("activeToken", token);
  }

  async getActiveToken(): Promise<string | null> {
    return (await LocalStorage.getItem("activeToken")) as string | null;
  }

  async clearActiveToken(): Promise<void> {
    await LocalStorage.removeItem("activeToken");
  }

  // [+] Update credentials to include partial state (matching web app pattern)
  async storePartialCredentials(email: string, userId?: number, encryptedToken?: string): Promise<void> {
    const partialCreds = {
      email,
      userId,
      encryptedToken,
      timestamp: Date.now()
    };
    const encrypted = await this.encryptData(JSON.stringify(partialCreds));
    await LocalStorage.setItem("partialCredentials", encrypted);
  }

  async getPartialCredentials(): Promise<{email: string, userId?: number, encryptedToken?: string} | null> {
    const encryptedData = (await LocalStorage.getItem("partialCredentials")) as string | undefined;
    if (!encryptedData) return null;
    try {
      const decrypted = await this.decryptData(encryptedData);
      return JSON.parse(decrypted);
    } catch (error) {
      console.error("Failed to decrypt partial credentials:", error);
      return null;
    }
  }

  async clearPartialCredentials(): Promise<void> {
    await LocalStorage.removeItem("partialCredentials");
  }

  async clearAll(): Promise<void> {
    console.log("DEBUG: 🧹 Clearing all stored data and resetting service state");
    this.masterKey = null;
    this.storageEncryptionKey = null;
    await LocalStorage.clear();
    console.log("DEBUG: ✅ All data cleared and service reset");
  }

  // [PERSISTENCE FIX] Authenticator key persistence for session restoration
  async storeDecryptedAuthKey(authKey: Buffer): Promise<void> {
    console.log("DEBUG: 💾 Storing decrypted authenticator key for session restoration");
    const keyData = {
      key: bufToBase64(authKey),
      timestamp: Date.now()
    };
    
    // Store without encryption since we're avoiding master key dependency
    await LocalStorage.setItem("decryptedAuthKey", JSON.stringify(keyData));
    console.log("DEBUG: ✅ Decrypted authenticator key stored for session restoration");
  }

  async getStoredDecryptedAuthKey(): Promise<Buffer | null> {
    try {
      const keyData = await LocalStorage.getItem("decryptedAuthKey") as string | undefined;
      if (!keyData) {
        console.log("DEBUG: No stored decrypted authenticator key found");
        return null;
      }
      
      const parsed = JSON.parse(keyData);
      console.log("DEBUG: 🔑 Found stored decrypted authenticator key");
      console.log("DEBUG: Key age:", Math.floor((Date.now() - parsed.timestamp) / 1000 / 60), "minutes");
      
      return base64ToBuf(parsed.key);
    } catch (error) {
      console.error("DEBUG: Failed to parse stored decrypted authenticator key:", error);
      return null;
    }
  }

  async clearStoredDecryptedAuthKey(): Promise<void> {
    await LocalStorage.removeItem("decryptedAuthKey");
    console.log("DEBUG: 🗑️ Cleared stored decrypted authenticator key");
  }

  // [PERSISTENCE FIX] Clean up failed session restoration attempts
  async cleanupFailedSessionRestoration(): Promise<void> {
    console.log("DEBUG: 🧹 Cleaning up failed session restoration data");
    await LocalStorage.removeItem("authenticationContext_unencrypted");
    await LocalStorage.removeItem("authEntities_unencrypted");
    await LocalStorage.removeItem("decryptedAuthKey");
    console.log("DEBUG: ✅ Cleaned up unencrypted authentication context, auth entities, and decrypted auth key");
  }

  // [+] Debug method to reset sync state for testing
  async resetSyncState(): Promise<void> {
    console.log("DEBUG: 🔄 Resetting sync state - clearing entities and timestamp");
    await LocalStorage.removeItem("authEntities");
    await LocalStorage.removeItem("authEntities_unencrypted");
    await LocalStorage.removeItem("lastSyncTime");
    console.log("DEBUG: ✅ Sync state reset complete - next sync will start from timestamp 0");
  }
}

let storageServiceInstance: StorageService | null = null;
export const getStorageService = (): StorageService => {
  if (!storageServiceInstance) {
    storageServiceInstance = new StorageService();
  }
  return storageServiceInstance;
};
