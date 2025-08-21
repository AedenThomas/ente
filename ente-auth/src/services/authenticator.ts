// src/services/authenticator.ts
import { getStorageService } from "./storage";
import { getApiClient } from "./api";
import { AuthData, AuthCode, UserCredentials } from "../types";
import { decryptAuthEntity, decryptAuthKey, encryptAuthKey, generateAuthenticatorKey } from "./crypto";
import { generateTOTP, getProgress, getRemainingSeconds } from "../utils/totp";
import { showToast, Toast } from "@raycast/api";

// [+] More robust URI parsing function based on official web app's implementation
function parseAuthDataFromUri(uriString: string, entityId: string, updatedAt: number): AuthData | null {
  try {
    // CRITICAL FIX: Handle JSON-encoded strings with extra quotes from server
    // The decrypted data sometimes comes as JSON-encoded: "otpauth://..." instead of otpauth://...
    let cleanedUri = uriString;
    
    // Check if the URI string is JSON-encoded (starts and ends with quotes)
    if (cleanedUri.startsWith('"') && cleanedUri.endsWith('"')) {
      console.log(`DEBUG: Detected JSON-encoded URI for entity ${entityId}, parsing...`);
      try {
        cleanedUri = JSON.parse(cleanedUri);
        console.log(`DEBUG: Successfully parsed JSON-encoded URI for entity ${entityId}`);
      } catch (jsonError) {
        console.warn(`DEBUG: Failed to parse JSON-encoded URI for entity ${entityId}:`, jsonError);
        // Continue with original string if JSON parsing fails
      }
    }
    
    // Handle potential encoding issues from older clients - legacy fix for # characters
    if (cleanedUri.includes("#")) {
      cleanedUri = cleanedUri.replaceAll("#", "%23");
    }
    
    const url = new URL(cleanedUri);
    console.log(`DEBUG: Parsing URI for entity ${entityId}: ${cleanedUri}`);

    // Parse type and path with browser compatibility fallbacks
    const [type, path] = parsePathname(url);
    
    const account = parseAccount(path);
    const issuer = parseIssuer(url, path);
    const secret = url.searchParams.get("secret");

    if (!secret) {
      console.warn(`Entity ${entityId} is missing a secret.`);
      return null;
    }

    // Parse numeric parameters with proper defaults
    const digits = parseInt(url.searchParams.get("digits") || (type === "steam" ? "5" : "6"), 10);
    const period = parseInt(url.searchParams.get("period") || "30", 10);
    const algorithm = parseAlgorithm(url);
    const counterParam = url.searchParams.get("counter");
    const counter = counterParam ? parseInt(counterParam, 10) : undefined;

    const result = {
      id: entityId,
      name: account || "Unknown Account",
      issuer: issuer || "Unknown",
      secret: secret.replace(/\s/g, "").toUpperCase(),
      type,
      algorithm,
      digits,
      period,
      counter,
      updatedAt,
    };
    
    console.log(`DEBUG: Successfully parsed entity ${entityId}:`, result);
    return result;
  } catch (error) {
    console.error(`Failed to parse URI for entity ${entityId}: "${uriString}"`, error);
    return null;
  }
}

// Helper function to parse type and pathname - handles browser compatibility issues
function parsePathname(url: URL): [type: AuthData["type"], path: string] {
  // Handle different browser URL parsing behaviors for otpauth:// scheme
  switch (url.host.toLowerCase()) {
    case "totp":
      return ["totp", url.pathname.toLowerCase()];
    case "hotp":
      return ["hotp", url.pathname.toLowerCase()];
    case "steam":
      return ["steam", url.pathname.toLowerCase()];
    default:
      break;
  }

  // Fallback parsing for browsers that put everything in pathname
  const p = url.pathname.toLowerCase();
  if (p.startsWith("//totp")) return ["totp", url.pathname.slice(6)];
  if (p.startsWith("//hotp")) return ["hotp", url.pathname.slice(6)];
  if (p.startsWith("//steam")) return ["steam", url.pathname.slice(7)];

  throw new Error(`Unsupported code or unparseable path "${url.pathname}"`);
}

// Parse account name from path
function parseAccount(path: string): string | undefined {
  let p = decodeURIComponent(path);
  if (p.startsWith("/")) p = p.slice(1);
  if (p.includes(":")) p = p.split(":").slice(1).join(":");
  return p;
}

// Parse issuer with robust fallback logic
function parseIssuer(url: URL, path: string): string {
  // If there is an "issuer" search param, use that
  let issuer = url.searchParams.get("issuer");
  if (issuer) {
    // Handle bug in old versions of Ente Auth app where issuer had "period" appended
    if (issuer.endsWith("period")) {
      issuer = issuer.substring(0, issuer.length - 6);
    }
    return issuer;
  }

  // Otherwise extract issuer from path prefix
  let p = decodeURIComponent(path);
  if (p.startsWith("/")) p = p.slice(1);

  if (p.includes(":")) p = p.split(":")[0]!;
  else if (p.includes("-")) p = p.split("-")[0]!;

  return p || "Unknown";
}

// Parse algorithm with proper validation
function parseAlgorithm(url: URL): AuthData["algorithm"] {
  switch (url.searchParams.get("algorithm")?.toLowerCase()) {
    case "sha256":
      return "sha256";
    case "sha512":
      return "sha512";
    default:
      return "sha1";
  }
}

export class AuthenticatorService {
  private storage = getStorageService();
  private cachedDecryptionKey: Buffer | null = null; // Changed to Buffer for consistency

  async init(): Promise<boolean> {
    console.log("DEBUG: --- Starting AuthenticatorService Init ---");
    
    try {
      // First, try traditional credentials-based initialization
      const credentials = await this.storage.getCredentials();
      const masterKey = await this.storage.getMasterKey();
      
      if (credentials && masterKey) {
        console.log("DEBUG: Using traditional credentials-based initialization");
        return await this.initWithCredentials(credentials, masterKey);
      }
      
      // Fallback: Try session restoration initialization
      console.log("DEBUG: No credentials/master key available, attempting session restoration initialization");
      return await this.initWithSessionRestoration();
      
    } catch (error) {
      console.error("DEBUG: AuthenticatorService init failed:", error);
      console.log("DEBUG: --- AuthenticatorService Init Complete (Failure) ---");
      return false;
    }
  }

  private async initWithCredentials(credentials: UserCredentials, masterKey: Buffer): Promise<boolean> {
    console.log("DEBUG: 🔐 Initializing with full credentials and master key");
    
    // Get authentication context
    const authContext = await this.storage.getAuthenticationContext();
    console.log("DEBUG: Retrieved authentication context:", {
      hasContext: !!authContext,
      userId: authContext?.userId,
      accountKey: authContext?.accountKey ? authContext.accountKey.substring(0, 20) + "..." : "none"
    });

    // Initialize API client with token and authentication context
    const apiClient = await getApiClient();
    if (credentials.token) {
      apiClient.setToken(credentials.token);
    }
    
    if (authContext) {
      apiClient.setAuthenticationContext(authContext);
      console.log("DEBUG: Set authentication context on API client");
    } else {
      console.warn("DEBUG: No authentication context available - this may cause API failures");
    }

    // Try to get/setup authenticator key
    try {
      await this.getDecryptionKey();
      console.log("DEBUG: Authenticator key initialized successfully");
    } catch (error) {
      console.error("DEBUG: Failed to initialize authenticator key:", error);
      // Don't fail init if we can't get the auth key yet - it might be created later
    }

    console.log("DEBUG: --- AuthenticatorService Init Complete (Success - Credentials) ---");
    return true;
  }

  private async initWithSessionRestoration(): Promise<boolean> {
    console.log("DEBUG: 🔄 Attempting session restoration initialization");
    
    // Check if we have authentication context (needed for API calls)
    const authContext = await this.storage.getAuthenticationContext();
    if (!authContext) {
      console.log("DEBUG: No authentication context available for session restoration");
      return false;
    }

    console.log("DEBUG: Retrieved authentication context for session restoration:", {
      userId: authContext.userId,
      accountKey: authContext.accountKey ? authContext.accountKey.substring(0, 20) + "..." : "none"
    });

    // Verify API client is properly configured
    const apiClient = await getApiClient();
    
    // Try to use stored decrypted authenticator key first
    const storedAuthKey = await this.storage.getStoredDecryptedAuthKey();
    if (storedAuthKey) {
      console.log("DEBUG: 🔑 Found stored decrypted authenticator key, using for session restoration");
      this.cachedDecryptionKey = storedAuthKey;
      console.log("DEBUG: --- AuthenticatorService Init Complete (Success - Session Restoration with Stored Key) ---");
      return true;
    }

    // Fallback: Try to fetch authenticator key from API
    console.log("DEBUG: No stored decrypted authenticator key, attempting to fetch from API");
    try {
      const authKey = await apiClient.getAuthKey();
      if (authKey) {
        console.log("DEBUG: ⚠️ Got encrypted auth key from API, but cannot decrypt without master key");
        console.log("DEBUG: This indicates a missing master key during session restoration");
        // We have the encrypted key but can't decrypt it without the master key
        // Store the encrypted key for when credentials become available
        await this.storage.storeAuthKey(authKey);
        console.log("DEBUG: Stored encrypted auth key for future use");
      }
    } catch (error) {
      console.log("DEBUG: Failed to fetch auth key from API during session restoration:", error);
    }

    // For now, continue without authenticator key - it will be initialized on first use
    console.log("DEBUG: 🤷 Proceeding without authenticator key - will initialize on first sync/access");
    console.log("DEBUG: --- AuthenticatorService Init Complete (Success - Session Restoration Partial) ---");
    return true;
  }

  private async getDecryptionKey(): Promise<Buffer> {
    if (this.cachedDecryptionKey) {
      console.log("DEBUG: Using cached authenticator decryption key.");
      return this.cachedDecryptionKey;
    }

    const apiClient = await getApiClient();
    // getMasterKey now returns a Buffer
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

          const newAuthenticatorKey = await generateAuthenticatorKey();
          const { encryptedKeyB64, headerB64 } = await encryptAuthKey(newAuthenticatorKey, masterKey);

          authKey = await apiClient.createAuthKey(encryptedKeyB64, headerB64);
          console.log("DEBUG: Created and stored new auth key on server.");

          this.cachedDecryptionKey = newAuthenticatorKey;
          await this.storage.storeAuthKey(authKey);

          // [PERSISTENCE FIX] Store decrypted key for session restoration
          try {
            await this.storage.storeDecryptedAuthKey(this.cachedDecryptionKey);
          } catch (error) {
            console.log("DEBUG: ⚠️ Failed to store new authenticator key for session restoration:", error);
          }

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

    this.cachedDecryptionKey = await decryptAuthKey(authKey.encryptedKey, authKey.header, masterKey);
    console.log("DEBUG: Successfully decrypted authenticator key.");
    
    // [PERSISTENCE FIX] Store decrypted key for session restoration
    try {
      await this.storage.storeDecryptedAuthKey(this.cachedDecryptionKey);
    } catch (error) {
      console.log("DEBUG: ⚠️ Failed to store decrypted authenticator key for session restoration:", error);
    }
    
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

      const currentEntities = await this.storage.getAuthEntities();
      const entityMap = new Map<string, AuthData>();
      currentEntities.forEach((e) => entityMap.set(e.id, e));
      console.log(`DEBUG: Starting with ${entityMap.size} local entities.`);

      // CRITICAL FIX: Follow web implementation pattern - start from 0 for initial sync
      let sinceTime = 0;
      const storedLastSync = await this.storage.getLastSyncTime();
      
      // Only use stored timestamp if we already have entities (not initial sync)
      if (currentEntities.length > 0 && storedLastSync > 0) {
        sinceTime = storedLastSync;
        console.log("DEBUG: Using stored sync timestamp for incremental sync:", sinceTime);
      } else {
        console.log("DEBUG: Starting initial sync from timestamp 0 (matching web implementation)");
        // Reset stored timestamp to 0 for clean initial sync
        await this.storage.storeLastSyncTime(0);
      }

      const batchSize = 500;
      let totalEntitiesProcessed = 0;
      let maxUpdatedAt = sinceTime;

      // Paginated sync matching web implementation
      while (true) {
        console.log(`DEBUG: Fetching batch since timestamp: ${sinceTime}, limit: ${batchSize}`);
        const { diff: entities } = await apiClient.getAuthDiff(sinceTime, batchSize);
        console.log(`DEBUG: Received ${entities.length} entities in this batch.`);

        if (entities.length === 0) {
          console.log("DEBUG: No more entities to sync, batch complete.");
          break;
        }

        // Process this batch of entities
        for (const entity of entities) {
          maxUpdatedAt = Math.max(maxUpdatedAt, entity.updatedAt);
          totalEntitiesProcessed++;
          
          if (entity.isDeleted) {
            entityMap.delete(entity.id);
            console.log(`DEBUG: Deleted entity ${entity.id}`);
          } else if (entity.encryptedData && entity.header) {
            try {
              const decryptedJson = await decryptAuthEntity(entity.encryptedData, entity.header, authenticatorKey);

              // Use the robust parsing function with JSON handling
              const authData = parseAuthDataFromUri(decryptedJson, entity.id, entity.updatedAt);
              if (authData) {
                entityMap.set(entity.id, authData);
                console.log(`DEBUG: Upserted entity ${entity.id} (${authData.issuer}:${authData.name})`);
              } else {
                console.warn(`DEBUG: Failed to parse URI for entity ${entity.id}, skipping`);
              }
            } catch (e) {
              console.error(`DEBUG: Failed to decrypt or parse entity ${entity.id}`, e);
            }
          }
        }

        // Update sinceTime for next batch (matching web implementation)
        sinceTime = maxUpdatedAt;
        
        // If we got fewer entities than batch size, we're done
        if (entities.length < batchSize) {
          console.log("DEBUG: Received partial batch, sync complete.");
          break;
        }
      }

      const updatedEntities = Array.from(entityMap.values());
      await this.storage.storeAuthEntities(updatedEntities);
      await this.storage.storeLastSyncTime(maxUpdatedAt);
      
      console.log(`DEBUG: Sync complete - processed ${totalEntitiesProcessed} changes, stored ${updatedEntities.length} entities. New sync time: ${maxUpdatedAt}`);

      if (totalEntitiesProcessed > 0) {
        toast.style = Toast.Style.Success;
        toast.title = `Synced ${totalEntitiesProcessed} updates`;
      } else {
        toast.style = Toast.Style.Success;
        toast.title = "Already up to date";
      }
      
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

  // ... (getAuthCodes remains the same)
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
        // HOTP codes don't have time-based expiration
        remainingSeconds = undefined;
        progress = undefined;
      } else {
        // Handles 'totp' and 'steam' - fix the type casting issue
        const totpType = entity.type === "steam" ? "steam" : "totp";
        code = generateTOTP(entity.secret, entity.period, entity.digits, entity.algorithm, totpType);
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

// [+] Make this a proper singleton to avoid re-instantiating the service
let authenticatorServiceInstance: AuthenticatorService | null = null;
export const getAuthenticatorService = (): AuthenticatorService => {
  if (!authenticatorServiceInstance) {
    authenticatorServiceInstance = new AuthenticatorService();
  }
  return authenticatorServiceInstance;
};
