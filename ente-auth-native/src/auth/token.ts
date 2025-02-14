import { LocalStorage } from "@raycast/api";
import { api } from "../services/api";
import { Token, TokenInfo, KeyAttributes } from "../types/auth";
import { decryptToken as cryptoDecryptToken, bytesToBase64, base64ToBytes } from "../utils/crypto";
import { sodium } from "../utils/sodium";

export interface TokenResponse extends Token {
  masterKeyEncryptedWithRecoveryKey?: string;
  masterKeyDecryptionNonce?: string;
  recoveryKeyEncryptedWithMasterKey?: string;
  recoveryKeyDecryptionNonce?: string;
}

export class TokenManager {
  private readonly tokenKey = "auth_token";
  private readonly userIdKey = "user_id";
  private readonly masterKeyKey = "master_key";
  private readonly encryptedTokenKey = "encrypted_token";
  private readonly keyAttributesKey = "key_attributes";
  private masterKey?: Uint8Array;

  async saveMasterKey(key: Uint8Array) {
    console.log("[TokenManager.saveMasterKey] First 5 bytes:", Array.from(key.slice(0, 5)));
    this.masterKey = key;
    const base64Key = Buffer.from(key).toString("base64");
    await LocalStorage.setItem(this.masterKeyKey, base64Key);
    console.log("[TokenManager.saveMasterKey] Master key saved successfully");
  }

  async getMasterKey(): Promise<Uint8Array | undefined> {
    if (this.masterKey) {
      console.log("[TokenManager.getMasterKey] Returning cached master key");
      return this.masterKey;
    }
    try {
      const base64Key = await LocalStorage.getItem<string>(this.masterKeyKey);
      if (!base64Key) {
        console.log("[TokenManager.getMasterKey] No master key found in storage");
        return undefined;
      }
      this.masterKey = Buffer.from(base64Key, "base64");
      console.log(
        "[TokenManager.getMasterKey] Retrieved master key from storage, first 5 bytes:",
        Array.from(this.masterKey.slice(0, 5))
      );
      return this.masterKey;
    } catch (error) {
      console.error("[TokenManager.getMasterKey] Failed to get master key:", error);
      return undefined;
    }
  }

  private async saveEncryptedTokenAndAttributes(encryptedToken: string, keyAttributes: any): Promise<void> {
    console.debug("[TokenManager.saveEncryptedTokenAndAttributes] Saving encrypted data:", {
      encryptedTokenLength: encryptedToken?.length,
      keyAttributeKeys: keyAttributes ? Object.keys(keyAttributes) : [],
    });

    await LocalStorage.setItem(this.encryptedTokenKey, encryptedToken);
    await LocalStorage.setItem(this.keyAttributesKey, JSON.stringify(keyAttributes));

    // Verify storage
    const savedToken = await LocalStorage.getItem<string>(this.encryptedTokenKey);
    const savedAttrs = await LocalStorage.getItem<string>(this.keyAttributesKey);

    if (!savedToken || savedToken !== encryptedToken || !savedAttrs) {
      console.error("[TokenManager.saveEncryptedTokenAndAttributes] Verification failed:", {
        hasToken: !!savedToken,
        tokenMatch: savedToken === encryptedToken,
        hasAttrs: !!savedAttrs,
      });
      throw new Error("Failed to save encrypted token data");
    }
  }

  async saveToken(response: TokenResponse): Promise<void> {
    console.log("[TokenManager.saveToken] Starting token save process:", {
      id: response.id,
      hasEncryptedToken: !!response.encryptedToken,
      hasKeyAttributes: !!response.keyAttributes,
      encryptedTokenLength: response.encryptedToken?.length,
      hasRecoveryKey: !!response.keyAttributes?.masterKeyEncryptedWithRecoveryKey,
      keyAttributeKeys: response.keyAttributes ? Object.keys(response.keyAttributes) : [],
      tokenResponseKeys: Object.keys(response),
    });

    try {
      const masterKey = await this.getMasterKey();
      if (!masterKey) {
        throw new Error("Master key not found");
      }

      console.debug("[TokenManager.saveToken] Prepared key attributes:", {
        originalKeys: response.keyAttributes ? Object.keys(response.keyAttributes) : [],
        mergedKeys: response.keyAttributes ? Object.keys(response.keyAttributes) : [],
        hasRecoveryData: !!response.keyAttributes?.masterKeyEncryptedWithRecoveryKey,
      });

      if (!response.encryptedToken || !response.keyAttributes) {
        throw new Error("Missing encrypted token or key attributes");
      }

      await this.saveEncryptedTokenAndAttributes(response.encryptedToken, response.keyAttributes);
      const decryptedTokenBytes = await cryptoDecryptToken(
        {
          ...response.keyAttributes,
          encryptedToken: response.encryptedToken,
        },
        masterKey
      );

      // Convert decrypted token bytes to URL-safe base64 string
      const token = bytesToBase64(decryptedTokenBytes, true); // true for URL-safe
      console.debug("[TokenManager.saveToken] Token decrypted:", {
        tokenLength: token.length,
        tokenPrefix: token.substring(0, 16),
        tokenSuffix: token.substring(token.length - 16),
        isUrlSafe: !token.includes("+") && !token.includes("/"),
        containsPlus: token.includes("+"),
        containsSlash: token.includes("/"),
        containsUnderscore: token.includes("_"),
        containsDash: token.includes("-"),
        containsEquals: token.includes("="),
        rawBytesLength: decryptedTokenBytes.length,
        expectedLength: 32, // Server expects 32 bytes
      });

      // Verify the token can be retrieved
      const verificationToken = await this.getToken();
      console.debug("[TokenManager.saveToken] Token saved and verified successfully:", {
        tokenLength: verificationToken?.length,
        isUrlSafe: verificationToken ? !verificationToken.includes("+") && !verificationToken.includes("/") : null,
        allStorageKeys: await this.getAllStorageKeys(),
        verificationTokenFormat: verificationToken
          ? {
              containsPlus: verificationToken.includes("+"),
              containsSlash: verificationToken.includes("/"),
              containsUnderscore: verificationToken.includes("_"),
              containsDash: verificationToken.includes("-"),
              containsEquals: verificationToken.includes("="),
            }
          : null,
      });

      await this.saveUserId(response.id);
    } catch (error) {
      console.error("[TokenManager.saveToken] Error saving token:", {
        error: error instanceof Error ? error.message : "Unknown error",
        type: error instanceof Error ? error.constructor.name : typeof error,
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  async getToken(): Promise<string | null> {
    console.log("[TokenManager.getToken] Getting token");
    try {
      const encryptedToken = await this.getStoredEncryptedToken();
      const keyAttributes = await this.getStoredKeyAttributes();
      const masterKey = await this.getMasterKey();

      console.debug("[TokenManager.getToken] Retrieved stored data:", {
        hasEncryptedToken: !!encryptedToken,
        encryptedTokenLength: encryptedToken?.length,
        hasKeyAttributes: !!keyAttributes,
        keyAttributeKeys: keyAttributes ? Object.keys(keyAttributes) : [],
        hasMasterKey: !!masterKey,
        masterKeyLength: masterKey?.length,
      });

      if (!encryptedToken || !keyAttributes || !masterKey) {
        console.error("[TokenManager.getToken] Missing required data:", {
          hasEncryptedToken: !!encryptedToken,
          hasKeyAttributes: !!keyAttributes,
          hasMasterKey: !!masterKey,
        });
        return null;
      }

      const decryptedTokenBytes = await cryptoDecryptToken(
        {
          ...keyAttributes,
          encryptedToken,
        },
        masterKey
      );

      // Convert decrypted token bytes to URL-safe base64 string
      const token = bytesToBase64(decryptedTokenBytes, true); // true for URL-safe
      console.debug("[TokenManager.getToken] Token decrypted:", {
        tokenLength: token.length,
        tokenPrefix: token.substring(0, 16),
        tokenSuffix: token.substring(token.length - 16),
        isUrlSafe: !token.includes("+") && !token.includes("/"),
        containsPlus: token.includes("+"),
        containsSlash: token.includes("/"),
        containsUnderscore: token.includes("_"),
        containsDash: token.includes("-"),
        containsEquals: token.includes("="),
        rawBytesLength: decryptedTokenBytes.length,
        expectedLength: 32, // Server expects 32 bytes
      });

      return token;
    } catch (error) {
      console.error("[TokenManager.getToken] Error getting token:", {
        error: error instanceof Error ? error.message : "Unknown error",
        type: error instanceof Error ? error.constructor.name : typeof error,
        stack: error instanceof Error ? error.stack : undefined,
      });
      return null;
    }
  }

  async clearToken(): Promise<void> {
    try {
      console.log("[TokenManager.clearToken] Clearing token...");
      await LocalStorage.removeItem(this.tokenKey);
      await LocalStorage.removeItem(this.encryptedTokenKey);
      await LocalStorage.removeItem(this.keyAttributesKey);
      await LocalStorage.removeItem(this.masterKeyKey);
      await LocalStorage.removeItem(this.userIdKey);
      this.masterKey = undefined;
      console.log("[TokenManager.clearToken] Token and related data cleared successfully");

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
      return userId ?? null;
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

  async getStoredEncryptedToken(): Promise<string | null> {
    try {
      const token = await LocalStorage.getItem<string>(this.encryptedTokenKey);
      console.debug("[TokenManager.getStoredEncryptedToken] Retrieved encrypted token:", {
        hasToken: !!token,
        length: token?.length,
      });
      return token || null;
    } catch (error) {
      console.error("[TokenManager.getStoredEncryptedToken] Error:", error);
      return null;
    }
  }

  async getStoredKeyAttributes(): Promise<any | null> {
    try {
      const attrs = await LocalStorage.getItem<string>(this.keyAttributesKey);
      console.debug("[TokenManager.getStoredKeyAttributes] Retrieved key attributes:", {
        hasAttributes: !!attrs,
        keys: attrs ? Object.keys(JSON.parse(attrs)) : [],
      });
      return attrs ? JSON.parse(attrs) : null;
    } catch (error) {
      console.error("[TokenManager.getStoredKeyAttributes] Error:", error);
      return null;
    }
  }

  private async getAllStorageKeys(): Promise<string[]> {
    try {
      const keys = ["auth_token", "user_id", "master_key", "encrypted_token", "key_attributes"];
      const existingKeys = await Promise.all(
        keys.map(async (key) => {
          const value = await LocalStorage.getItem(key);
          return value ? key : null;
        })
      );
      return existingKeys.filter((key): key is string => key !== null);
    } catch (error) {
      console.error("[TokenManager.getAllStorageKeys] Error getting storage keys:", error);
      return [];
    }
  }
}
