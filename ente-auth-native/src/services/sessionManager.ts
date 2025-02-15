import { TokenManager } from "../auth/token";
import { api } from "../services/api";

export class SessionManager {
  private static instance: SessionManager | null = null;
  private tokenManager: TokenManager;
  private refreshInterval: NodeJS.Timeout | null = null;
  private readonly REFRESH_INTERVAL = 5 * 60 * 1000; // 5 minutes
  private readonly REFRESH_THRESHOLD = 10 * 60 * 1000; // 10 minutes

  constructor() {
    console.log("[SessionManager] Creating new instance");
    this.tokenManager = new TokenManager();
  }

  public static getInstance(): SessionManager {
    if (!SessionManager.instance) {
      SessionManager.instance = new SessionManager();
    }
    return SessionManager.instance;
  }

  public static createInstance(): SessionManager {
    return new SessionManager();
  }

  async getToken(): Promise<string | null> {
    console.log("[SessionManager.getToken] Getting token from token manager");
    try {
      const token = await this.tokenManager.getToken();
      console.debug("[SessionManager.getToken] Token state:", {
        hasToken: !!token,
        tokenLength: token?.length,
        tokenPrefix: token ? token.substring(0, 10) + "..." : null,
      });
      return token;
    } catch (error) {
      console.error("[SessionManager.getToken] Error getting token:", error);
      return null;
    }
  }

  async startTokenRefreshSchedule(): Promise<void> {
    console.log("[SessionManager.startTokenRefreshSchedule] Starting refresh schedule");

    // Get initial state
    const encryptedToken = await this.tokenManager.getStoredEncryptedToken();
    const keyAttributes = await this.tokenManager.getStoredKeyAttributes();
    const masterKey = await this.tokenManager.getMasterKey();

    console.debug("[SessionManager.startTokenRefreshSchedule] Initial state:", {
      hasEncryptedToken: !!encryptedToken,
      encryptedTokenLength: encryptedToken?.length,
      keyAttributeKeys: keyAttributes ? Object.keys(keyAttributes) : [],
      hasMasterKey: !!masterKey,
      masterKeyLength: masterKey?.length,
    });

    // Clear any existing refresh interval
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }

    // Set up periodic refresh
    this.refreshInterval = setInterval(async () => {
      try {
        await this.refreshToken();
      } catch (error) {
        console.error("[SessionManager.refreshInterval] Refresh failed:", {
          error: error instanceof Error ? error.message : "Unknown error",
          type: error instanceof Error ? error.constructor.name : typeof error,
          stack: error instanceof Error ? error.stack : undefined,
        });
      }
    }, this.REFRESH_INTERVAL);

    console.debug("[SessionManager.startTokenRefreshSchedule] Refresh schedule started with interval:", {
      intervalMs: this.REFRESH_INTERVAL,
      thresholdMs: this.REFRESH_THRESHOLD,
    });
  }

  async refreshToken(): Promise<void> {
    console.log("[SessionManager.refreshToken] Starting token refresh");
    try {
      const token = await this.tokenManager.getToken();
      if (!token) {
        console.error("[SessionManager.refreshToken] No token to refresh");
        return;
      }

      console.debug("[SessionManager.refreshToken] Refreshing token:", {
        tokenLength: token.length,
        tokenPrefix: token.substring(0, 16),
        tokenSuffix: token.substring(token.length - 16),
        isUrlSafe: !token.includes("+") && !token.includes("/"),
      });

      const encryptedToken = await this.tokenManager.getStoredEncryptedToken();
      const keyAttributes = await this.tokenManager.getStoredKeyAttributes();
      const masterKey = await this.tokenManager.getMasterKey();

      if (!encryptedToken || !keyAttributes || !masterKey) {
        console.error("[SessionManager.refreshToken] Missing required data:", {
          hasEncryptedToken: !!encryptedToken,
          hasKeyAttributes: !!keyAttributes,
          hasMasterKey: !!masterKey,
        });
        throw new Error("Missing required data for token refresh");
      }

      try {
        const response = await api.refreshToken({ token });
        if (response?.encryptedToken && response?.keyAttributes) {
          await this.tokenManager.saveToken(response);
          console.log("[SessionManager.refreshToken] Token refreshed and saved successfully");
        } else {
          throw new Error("Invalid response from refresh token API");
        }
      } catch (error) {
        const isUnauthorized =
          error instanceof Error && (error.message.includes("401") || error.message.includes("404"));

        console.error("[SessionManager.refreshToken] Token refresh failed:", {
          error: error instanceof Error ? error.message : "Unknown error",
          type: error instanceof Error ? error.constructor.name : typeof error,
          isUnauthorized,
          stack: error instanceof Error ? error.stack : undefined,
        });

        if (isUnauthorized) {
          await this.tokenManager.clearToken();
        }
        throw error;
      }
    } catch (error) {
      console.error("[SessionManager.refreshToken] Error:", error);
      throw error;
    }
  }

  async stopTokenRefreshSchedule(): Promise<void> {
    console.log("[SessionManager.stopTokenRefreshSchedule] Stopping refresh schedule");
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  async logout(): Promise<void> {
    console.log("[SessionManager.logout] Starting logout process");
    try {
      await api.logout();
    } catch (error) {
      console.error("[SessionManager.logout] Logout request failed:", error);
      // Continue with cleanup even if request fails
    }

    await this.stopTokenRefreshSchedule();
    await this.tokenManager.clearToken();
  }
}
