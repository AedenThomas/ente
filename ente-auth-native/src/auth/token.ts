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
  private masterKey?: Uint8Array;

  async saveMasterKey(key: Uint8Array) {
    this.masterKey = key;
  }

  async saveToken(keyAttributes: KeyAttributes, encryptedToken: string) {
    try {
      console.log("Starting token decryption process");
      if (!this.masterKey) {
        throw new Error("Master key not found");
      }

      // Add the encrypted token to the key attributes
      const keyAttributesWithToken = {
        ...keyAttributes,
        encryptedToken,
      };

      const token = await decryptToken(keyAttributesWithToken, this.masterKey);
      await LocalStorage.setItem(STORAGE_KEYS.TOKEN, token);
      console.log("Token saved successfully");
    } catch (error) {
      console.error("Failed to decrypt token:", error);
      throw error;
    }
  }

  async getToken(): Promise<string | undefined> {
    return LocalStorage.getItem(STORAGE_KEYS.TOKEN);
  }

  async clearToken() {
    await LocalStorage.removeItem(STORAGE_KEYS.TOKEN);
    this.masterKey = undefined;
  }

  async saveUserId(userId: string): Promise<void> {
    await LocalStorage.setItem(STORAGE_KEYS.USER_ID, userId);
  }

  async getUserId(): Promise<string | undefined> {
    return LocalStorage.getItem(STORAGE_KEYS.USER_ID);
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
