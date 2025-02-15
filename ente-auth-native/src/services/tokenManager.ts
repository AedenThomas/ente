import { LocalStorage } from "@raycast/api";
import { decryptToken, bytesToBase64 } from "../utils/crypto";
import { KeyAttributes, TokenResponse } from "../types/auth";

const TOKEN_KEY = "auth_token";
const MASTER_KEY_KEY = "master_key";
const KEY_ATTRIBUTES_KEY = "key_attributes";
const ENCRYPTED_TOKEN_KEY = "encrypted_token";

export class TokenManager {
  private storage: typeof LocalStorage;
  private masterKey?: Uint8Array;

  constructor() {
    this.storage = LocalStorage;
  }

  async getMasterKey(): Promise<Uint8Array | undefined> {
    if (this.masterKey) {
      return this.masterKey;
    }
    const base64Key = await this.storage.getItem<string>(MASTER_KEY_KEY);
    if (!base64Key) {
      return undefined;
    }
    this.masterKey = Buffer.from(base64Key, "base64");
    return this.masterKey;
  }

  async getToken(): Promise<string | null> {
    try {
      const encryptedToken = await this.storage.getItem<string>(TOKEN_KEY);
      const keyAttributesStr = await this.storage.getItem<string>(KEY_ATTRIBUTES_KEY);
      const masterKey = await this.getMasterKey();

      if (!encryptedToken || !keyAttributesStr || !masterKey) {
        console.log("[TokenManager] Missing required data:", {
          hasEncryptedToken: !!encryptedToken,
          hasKeyAttributes: !!keyAttributesStr,
          hasMasterKey: !!masterKey,
        });
        return null;
      }

      const keyAttributes = JSON.parse(keyAttributesStr) as KeyAttributes;

      console.log("[TokenManager] Decrypting token:", {
        encryptedTokenLength: encryptedToken.length,
        encryptedTokenPrefix: encryptedToken.substring(0, 10),
        encryptedTokenSuffix: encryptedToken.substring(encryptedToken.length - 10),
        keyAttributesKeys: Object.keys(keyAttributes),
      });

      const decryptedTokenBytes = await decryptToken(
        {
          ...keyAttributes,
          encryptedToken,
        },
        masterKey
      );

      console.log("[TokenManager] Token decrypted:", {
        decryptedBytesLength: decryptedTokenBytes.length,
        expectedBytesLength: 32,
        firstBytes: Array.from(decryptedTokenBytes.slice(0, 5)),
      });

      const token = bytesToBase64(decryptedTokenBytes, true);
      console.log("[TokenManager] Token converted to URL-safe base64:", {
        tokenLength: token.length,
        tokenPrefix: token.substring(0, 10),
        tokenSuffix: token.substring(token.length - 10),
        containsPlus: token.includes("+"),
        containsSlash: token.includes("/"),
        containsUnderscore: token.includes("_"),
        containsDash: token.includes("-"),
        containsEquals: token.includes("="),
      });

      return token;
    } catch (error) {
      console.error("[TokenManager] Failed to get token:", {
        error: error instanceof Error ? error.message : "Unknown error",
        stack: error instanceof Error ? error.stack : undefined,
      });
      return null;
    }
  }

  async saveToken(response: TokenResponse): Promise<void> {
    try {
      console.log("[TokenManager.saveToken] Saving token response:", {
        hasEncryptedToken: !!response.encryptedToken,
        hasKeyAttributes: !!response.keyAttributes,
        encryptedTokenLength: response.encryptedToken?.length,
      });

      if (!response.encryptedToken || !response.keyAttributes) {
        throw new Error("Missing encrypted token or key attributes");
      }

      await this.storage.setItem(ENCRYPTED_TOKEN_KEY, response.encryptedToken);
      await this.storage.setItem(KEY_ATTRIBUTES_KEY, JSON.stringify(response.keyAttributes));

      console.log("[TokenManager.saveToken] Token data saved successfully");
    } catch (error) {
      console.error("[TokenManager.saveToken] Failed to save token:", {
        error: error instanceof Error ? error.message : "Unknown error",
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }
}
