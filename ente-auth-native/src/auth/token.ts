import { LocalStorage } from "@raycast/api";
import { api } from "../services/api";
import { Token, TokenInfo, KeyAttributes } from "../types/auth";
import { decryptToken } from "../utils/crypto";

const STORAGE_KEYS = {
  TOKEN: "token",
  USER_ID: "user_id",
  MASTER_KEY: "master_key",
};

export class TokenManager {
  private readonly tokenKey = "auth_token";
  private readonly userIdKey = "user_id";
  private readonly masterKeyKey = "master_key";
  private masterKey?: Uint8Array;

  async saveMasterKey(key: Uint8Array) {
    console.log("[TokenManager.saveMasterKey] First 5 bytes:", Array.from(key.slice(0, 5)));
    this.masterKey = key;
    // Convert to base64 for storage
    const base64Key = Buffer.from(key).toString("base64");
    await LocalStorage.setItem(this.masterKeyKey, base64Key);
  }

  async getMasterKey(): Promise<Uint8Array | undefined> {
    if (this.masterKey) {
      return this.masterKey;
    }
    try {
      const base64Key = await LocalStorage.getItem(this.masterKeyKey);
      if (!base64Key) {
        return undefined;
      }
      this.masterKey = Buffer.from(base64Key, "base64");
      return this.masterKey;
    } catch (error) {
      console.error("[TokenManager.getMasterKey] Failed to get master key:", error);
      return undefined;
    }
  }

  async saveToken(tokenResponse: Token): Promise<void> {
    try {
      console.log("[TokenManager.saveToken] Starting token save process");
      console.log("[TokenManager.saveToken] Token response:", {
        id: tokenResponse.id,
        hasEncryptedToken: !!tokenResponse.encryptedToken,
        hasKeyAttributes: !!tokenResponse.keyAttributes,
      });

      const masterKey = await this.getMasterKey();
      if (!masterKey) {
        console.error("[TokenManager.saveToken] Master key not found");
        throw new Error("Master key not found");
      }

      if (!tokenResponse.encryptedToken || !tokenResponse.keyAttributes) {
        console.error("[TokenManager.saveToken] Encrypted token or key attributes missing");
        throw new Error("Encrypted token or key attributes missing");
      }

      // Decrypt the token
      console.log("[TokenManager.saveToken] Decrypting token with key attributes");
      const tokenBytes = await decryptToken(
        {
          ...tokenResponse.keyAttributes,
          encryptedToken: tokenResponse.encryptedToken,
        },
        masterKey
      );

      // Convert token bytes to base64 string
      const token = Buffer.from(tokenBytes).toString("base64");
      console.log("[TokenManager.saveToken] Token decrypted successfully");

      // Log token details for debugging
      console.log("[TokenManager.saveToken] Token details:", {
        length: token.length,
        firstChars: token.substring(0, 10),
        lastChars: token.substring(token.length - 10),
      });

      try {
        await LocalStorage.setItem(this.tokenKey, token);
        console.log("[TokenManager.saveToken] Token saved successfully");
      } catch (error) {
        console.error("[TokenManager.saveToken] Failed to save token:", error);
        throw error;
      }

      // Verify the saved token
      const savedToken = await this.getToken();
      console.log("[TokenManager.saveToken] Verification - Token retrieved:", {
        saved: !!savedToken,
        matchesOriginal: savedToken === token,
      });

      if (!savedToken) {
        throw new Error("Failed to verify saved token");
      }
    } catch (error) {
      console.error("[TokenManager.saveToken] Failed to save token:", error);
      throw error;
    }
  }

  async getToken(): Promise<string | null> {
    try {
      console.log("[TokenManager.getToken] Getting token...");
      const token = await LocalStorage.getItem<string>(this.tokenKey);
      console.log("[TokenManager.getToken] Token retrieved:", {
        exists: !!token,
        length: token?.length,
      });
      return token;
    } catch (error) {
      console.error("[TokenManager.getToken] Error retrieving token:", error);
      return null;
    }
  }

  async clearToken(): Promise<void> {
    try {
      console.log("[TokenManager.clearToken] Clearing token...");
      await LocalStorage.removeItem(this.tokenKey);
      console.log("[TokenManager.clearToken] Token cleared successfully");

      // Verify token is cleared
      const token = await this.getToken();
      console.log("[TokenManager.clearToken] Verification - Token is cleared:", !token);
    } catch (error) {
      console.error("[TokenManager.clearToken] Error clearing token:", error);
      throw error;
    }
  }

  async saveUserId(userId: string): Promise<void> {
    try {
      console.log("[TokenManager.saveUserId] Saving user ID:", userId);
      await LocalStorage.setItem(this.userIdKey, userId);
      console.log("[TokenManager.saveUserId] User ID saved successfully");
    } catch (error) {
      console.error("[TokenManager.saveUserId] Error saving user ID:", error);
      throw error;
    }
  }

  async getUserId(): Promise<string | null> {
    try {
      const userId = await LocalStorage.getItem<string>(this.userIdKey);
      console.log("[TokenManager.getUserId] User ID retrieved:", !!userId);
      return userId;
    } catch (error) {
      console.error("[TokenManager.getUserId] Error retrieving user ID:", error);
      return null;
    }
  }

  async getActiveSessions(): Promise<TokenInfo[]> {
    const userId = await this.getUserId();
    if (!userId) {
      throw new Error("User ID not found");
    }
    return await api.getActiveSessions(userId);
  }

  async terminateSession(token: string): Promise<void> {
    const userId = await this.getUserId();
    if (!userId) {
      throw new Error("User ID not found");
    }
    await api.terminateSession(userId, token);
  }

  async terminateAllOtherSessions(): Promise<void> {
    const currentToken = await this.getToken();
    if (!currentToken) {
      throw new Error("No active session");
    }
    const userId = await this.getUserId();
    if (!userId) {
      throw new Error("User ID not found");
    }
    await api.terminateAllOtherSessions(userId, currentToken);
  }
}
