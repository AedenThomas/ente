import { getStorageService } from "./storage";
import { getApiClient } from "./api";
import { AuthData, AuthCode } from "../types";
import { decryptAuthEntity, decryptAuthKey, encryptAuthKey, generateAuthenticatorKey } from "./crypto";
import { generateTOTP, getProgress, getRemainingSeconds } from "../utils/totp";
import { showToast, Toast } from "@raycast/api";

export class AuthenticatorService {
  private storage = getStorageService();
  private cachedDecryptionKey: Uint8Array | null = null;

  private async getDecryptionKey(): Promise<Uint8Array> {
    if (this.cachedDecryptionKey) {
      console.log("DEBUG: Using cached authenticator decryption key.");
      return this.cachedDecryptionKey;
    }

    const apiClient = await getApiClient();
    const masterKey = await this.storage.getMasterKey();
    if (!masterKey) {
      throw new Error("Master key not available for getting decryption key.");
    }

    let authKey = await this.storage.getAuthKey();
    if (!authKey) {
      console.log("DEBUG: No local auth key found. Fetching from API...");
      try {
        authKey = await apiClient.getAuthKey();
        console.log("DEBUG: Fetched auth key from API.");
      } catch (error) {
        if ((error as Error).message === "AuthenticatorKeyNotFound") {
          console.log("DEBUG: No auth key on server, creating a new one.");
          const toast = await showToast({ style: Toast.Style.Animated, title: "Setting up authenticator..." });
          const newAuthenticatorKey = generateAuthenticatorKey();
          const { encryptedKeyB64, headerB64 } = encryptAuthKey(newAuthenticatorKey, masterKey);

          authKey = await apiClient.createAuthKey(encryptedKeyB64, headerB64);
          console.log("DEBUG: Created and stored new auth key on server.");

          this.cachedDecryptionKey = newAuthenticatorKey;
          await this.storage.storeAuthKey(authKey);

          toast.style = Toast.Style.Success;
          toast.title = "Authenticator setup complete";
          return this.cachedDecryptionKey;
        }
        throw error;
      }
      await this.storage.storeAuthKey(authKey);
    } else {
      console.log("DEBUG: Using auth key from local storage.");
    }

    this.cachedDecryptionKey = decryptAuthKey(authKey.encryptedKey, authKey.header, masterKey);
    console.log("DEBUG: Successfully decrypted authenticator key.");
    return this.cachedDecryptionKey;
  }

  async syncAuthenticator(): Promise<AuthData[]> {
    const toast = await showToast({
      style: Toast.Style.Animated,
      title: "Syncing...",
    });
    console.log("DEBUG: --- Starting Sync ---");

    try {
      const apiClient = await getApiClient();
      const authenticatorKey = await this.getDecryptionKey();

      const lastSync = await this.storage.getLastSyncTime();
      console.log("DEBUG: Syncing since timestamp:", lastSync);
      const { diff: entities } = await apiClient.getAuthDiff(lastSync);
      console.log(`DEBUG: Received ${entities.length} entities from diff.`);

      if (entities.length === 0) {
        toast.style = Toast.Style.Success;
        toast.title = "Already up to date";
        console.log("DEBUG: --- Sync Finished (No new data) ---");
        return await this.storage.getAuthEntities();
      }

      const currentEntities = await this.storage.getAuthEntities();
      const entityMap = new Map<string, AuthData>();

      currentEntities.forEach((e) => entityMap.set(e.id, e));
      console.log(`DEBUG: Starting with ${entityMap.size} local entities.`);

      let maxUpdatedAt = lastSync;
      for (const entity of entities) {
        maxUpdatedAt = Math.max(maxUpdatedAt, entity.updatedAt);
        if (entity.isDeleted) {
          entityMap.delete(entity.id);
          console.log(`DEBUG: Deleted entity ${entity.id}`);
        } else if (entity.encryptedData && entity.header) {
          try {
            const decryptedJson = decryptAuthEntity(entity.encryptedData, entity.header, authenticatorKey);

            // The decrypted data is a URI string, need to parse it.
            const parsedUri = new URL(decryptedJson);
            const secret = parsedUri.searchParams.get("secret");

            // Handle different URI path formats
            const pathParts = parsedUri.pathname.substring(1).split(":");
            const issuerFromPath = pathParts.length > 1 ? decodeURIComponent(pathParts[0]) : "";
            const accountFromPath = decodeURIComponent(pathParts.pop() || "");

            const issuer = parsedUri.searchParams.get("issuer") || issuerFromPath || "Unknown";
            const account = accountFromPath;

            if (secret) {
              const authData: AuthData = {
                id: entity.id,
                name: account,
                issuer: issuer,
                secret: secret.replace(/\s/g, "").toUpperCase(),
                type: parsedUri.host as "totp" | "hotp" | "steam",
                algorithm: (parsedUri.searchParams.get("algorithm")?.toLowerCase() || "sha1") as
                  | "sha1"
                  | "sha256"
                  | "sha512",
                digits: parseInt(parsedUri.searchParams.get("digits") || "6", 10),
                period: parseInt(parsedUri.searchParams.get("period") || "30", 10),
                counter: parsedUri.searchParams.get("counter")
                  ? parseInt(parsedUri.searchParams.get("counter")!, 10)
                  : undefined,
                updatedAt: entity.updatedAt,
              };
              entityMap.set(entity.id, authData);
              console.log(`DEBUG: Upserted entity ${entity.id} (${issuer}:${account})`);
            } else {
              console.warn(`DEBUG: Entity ${entity.id} decrypted but has no secret.`);
            }
          } catch (e) {
            console.error(`DEBUG: Failed to decrypt or parse entity ${entity.id}`, e);
          }
        }
      }

      const updatedEntities = Array.from(entityMap.values());
      await this.storage.storeAuthEntities(updatedEntities);
      await this.storage.storeLastSyncTime(maxUpdatedAt);
      console.log(`DEBUG: Stored ${updatedEntities.length} entities. New sync time: ${maxUpdatedAt}`);

      toast.style = Toast.Style.Success;
      toast.title = "Sync complete";
      console.log("DEBUG: --- Sync Finished (Success) ---");
      return updatedEntities;
    } catch (error) {
      toast.style = Toast.Style.Failure;
      toast.title = "Sync failed";
      toast.message = error instanceof Error ? error.message : "An unknown error occurred";
      console.error("Sync error:", error);
      console.log("DEBUG: --- Sync Finished (Failure) ---");
      return this.storage.getAuthEntities();
    }
  }

  async getAuthCodes(): Promise<AuthCode[]> {
    let entities = await this.storage.getAuthEntities();
    console.log(`DEBUG: getAuthCodes found ${entities.length} local entities.`);

    if (entities.length === 0) {
      console.log("DEBUG: No local entities, triggering a sync.");
      entities = await this.syncAuthenticator();
    }

    return entities.map((entity) => {
      let code: string;
      let remainingSeconds: number | undefined;
      let progress: number | undefined;

      // Note: HOTP is not fully supported in this simplified version as it requires counter updates.
      if (entity.type === "hotp") {
        code = "------";
      } else {
        // Handles 'totp' and 'steam'
        code = generateTOTP(entity.secret, entity.period, entity.digits, entity.algorithm, entity.type);
        remainingSeconds = getRemainingSeconds(entity.period);
        progress = getProgress(entity.period);
      }

      return {
        ...entity,
        code,
        remainingSeconds,
        progress,
      };
    });
  }
}

export const getAuthenticatorService = (): AuthenticatorService => {
  return new AuthenticatorService();
};
