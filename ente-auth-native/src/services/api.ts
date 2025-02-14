import { environment } from "../config/environment";
import { AuthError, PasskeySession, PasskeyVerificationResult, SRPAttributes, Token, TokenInfo } from "../types/auth";
import { open } from "@raycast/api";
import fetch from "node-fetch";
import type { RequestInit, HeadersInit } from "node-fetch";
import { SessionManager } from "../auth/session";
import { TokenManager } from "../auth/token";
import { bytesToBase64 } from "../utils/crypto";

type ExtendedHeaders = HeadersInit & {
  [key: string]: string | undefined;
};

class ApiService {
  private baseUrl: string;
  private sessionManager: SessionManager;
  private tokenManager: TokenManager;

  constructor() {
    this.baseUrl = environment.apiUrl;
    this.sessionManager = new SessionManager();
    this.tokenManager = new TokenManager();
  }

  private async getAuthHeaders(): Promise<HeadersInit> {
    const token = await this.tokenManager.getToken();
    if (!token) {
      return { "Content-Type": "application/json" };
    }

    console.log("[API.getAuthHeaders] Using token:", {
      length: token.length,
      prefix: token.substring(0, 16),
      suffix: token.substring(token.length - 16),
    });

    return {
      "Content-Type": "application/json",
      "X-Auth-Token": token, // Use URL-safe base64 token directly
    };
  }

  async request<T>(endpoint: string, options: RequestInit = {}, retryCount = 0): Promise<T> {
    console.log(`[API.request] Making request to: ${this.baseUrl}${endpoint}`);

    // Add debug logging for token state
    const currentToken = await this.tokenManager.getToken();
    console.debug("[API.request] Current token state:", {
      hasToken: !!currentToken,
      tokenLength: currentToken?.length,
      endpoint,
      method: options.method,
      isRefreshRequest: endpoint.includes("/session-refresh"),
      retryCount,
    });

    const headers = await this.getAuthHeaders();
    console.debug("[API.request] Request headers:", {
      hasAuthToken: !!headers["X-Auth-Token"],
      authTokenLength: headers["X-Auth-Token"]?.length,
      allHeaders: Object.keys(headers),
    });

    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        headers: {
          ...headers,
          ...options.headers,
        },
      });

      console.debug("[API.request] Response:", {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
      });

      const text = await response.text();
      console.debug("[API.request] Response text:", {
        length: text.length,
        preview: text.substring(0, 200) + (text.length > 200 ? "..." : ""),
        isJSON: text.startsWith("{") || text.startsWith("["),
      });

      if (!response.ok) {
        // Only attempt refresh if:
        // 1. Got 401
        // 2. Not already a refresh request
        // 3. Not already retrying
        // 4. Have current token
        if (response.status === 401 && !endpoint.includes("/session-refresh") && retryCount === 0 && currentToken) {
          console.log("[API.request] Got 401, attempting token refresh");
          try {
            const refreshResponse = await this.refreshToken();

            if (refreshResponse?.encryptedToken && refreshResponse?.keyAttributes) {
              await this.tokenManager.saveToken(refreshResponse);
              console.log("[API.request] Token refreshed successfully, retrying original request");
              return this.request(endpoint, options, retryCount + 1);
            }
          } catch (error) {
            console.error("[API.request] Token refresh failed:", {
              error: error instanceof Error ? error.message : "Unknown error",
              type: error instanceof Error ? error.constructor.name : typeof error,
              status: error instanceof Error ? (error as any).status : undefined,
              stack: error instanceof Error ? error.stack : undefined,
              endpoint,
              responseStatus: response.status,
            });

            // Only clear token on auth errors
            if (error instanceof Error && error.message.includes("401")) {
              await this.tokenManager.clearToken();
            }
          }
        }

        // Add more context to error message
        const errorMessage = `Request failed: ${response.status} ${text}`;
        console.error("[API.request] Request failed:", {
          status: response.status,
          endpoint,
          text: text.substring(0, 200),
          headers: response.headers,
        });
        throw new Error(errorMessage);
      }

      // Only parse as JSON if we have content and it looks like JSON
      if (text && (text.startsWith("{") || text.startsWith("["))) {
        try {
          return JSON.parse(text);
        } catch (error) {
          console.error("[API.request] Failed to parse JSON response:", error);
          throw new Error("Invalid JSON response");
        }
      }
      return null as T;
    } catch (error) {
      console.error("[API.request] Request error:", {
        endpoint,
        error: error instanceof Error ? error.message : "Unknown error",
        type: error instanceof Error ? error.constructor.name : typeof error,
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  private async refreshToken(): Promise<void> {
    try {
      const response = await this.request({
        endpoint: "/users/session/refresh", // Updated endpoint
        method: "POST",
        isRefreshRequest: true,
      });

      if (response.ok) {
        const data = await response.json();
        if (data.token) {
          await this.tokenManager.setToken(data.token);
        }
      } else {
        throw new Error(`Token refresh failed: ${response.status} ${await response.text()}`);
      }
    } catch (error) {
      console.error("[API.refreshToken] Error refreshing token:", {
        error: error instanceof Error ? error.message : "Unknown error",
        type: error?.constructor?.name,
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  async getSRPAttributes(email: string): Promise<SRPAttributes> {
    const response = await this.request<{ attributes: SRPAttributes }>(
      `/users/srp/attributes?email=${encodeURIComponent(email)}`
    );
    return response.attributes;
  }

  async createSRPSession(srpUserID: string, srpA: string): Promise<{ sessionID: string; srpB: string }> {
    return this.request("/users/srp/create-session", {
      method: "POST",
      body: JSON.stringify({ srpUserID, srpA }),
    });
  }

  async verifySRPSession(sessionID: string, srpUserID: string, srpM1: string): Promise<SRPSession> {
    console.log("[api.verifySRPSession] Starting session verification:", {
      sessionID,
      srpUserID,
      srpM1Length: srpM1.length,
      srpM1FirstChars: srpM1.substring(0, 10),
      srpM1Base64: srpM1,
      requestBody: {
        sessionID,
        srpUserID,
        srpM1,
      },
    });

    const response = await this.request<SRPSession>("/users/srp/verify-session", {
      method: "POST",
      body: JSON.stringify({
        sessionID,
        srpUserID,
        srpM1, // M1 is already base64 encoded
      }),
    });

    console.log("[api.verifySRPSession] Session verification response:", {
      hasResponse: !!response,
      hasKeyAttributes: !!response?.keyAttributes,
      hasEncryptedToken: !!response?.encryptedToken,
      hasM2: !!response?.srpM2,
      m2Length: response?.srpM2?.length,
      m2FirstChars: response?.srpM2?.substring(0, 10),
      m2Base64: response?.srpM2,
      responseKeys: response ? Object.keys(response) : [],
    });

    return response;
  }

  async sendEmailOTP(email: string): Promise<void> {
    await this.request("/users/ott", {
      method: "POST",
      body: JSON.stringify({
        email,
        purpose: "login",
      }),
    });
  }

  async verifyEmailOTP(email: string, otp: string): Promise<Token> {
    return this.request("/users/verify-email", {
      method: "POST",
      body: JSON.stringify({
        email,
        ott: otp,
      }),
    });
  }

  async beginPasskeyVerification(sessionID: string): Promise<PasskeySession> {
    return this.request(`/users/two-factor/passkeys/begin?sessionID=${sessionID}`);
  }

  async checkPasskeyStatus(passkeySessionID: string): Promise<PasskeyVerificationResult> {
    return this.request(`/users/two-factor/passkeys/get-token?sessionID=${passkeySessionID}`);
  }

  async logout(): Promise<void> {
    return this.request("/users/logout", { method: "POST" });
  }

  async getActiveSessions(userId: string): Promise<TokenInfo[]> {
    return this.request(`/users/${userId}/sessions`);
  }

  async terminateSession(userId: string, token: string): Promise<void> {
    return this.request(`/users/${userId}/sessions/${token}`, {
      method: "DELETE",
    });
  }

  async terminateAllOtherSessions(userId: string, currentToken: string): Promise<void> {
    return this.request(`/users/${userId}/sessions`, {
      method: "DELETE",
      headers: {
        "X-Current-Token": currentToken,
      },
    });
  }

  async openUrl(url: string): Promise<void> {
    await open(url);
  }

  async getAuthenticatorKey(): Promise<AuthenticatorKey> {
    return this.request<AuthenticatorKey>("/authenticator/key");
  }

  async getAuthenticatorCodes(): Promise<AuthenticatorCode[]> {
    return this.request<AuthenticatorCode[]>("/authenticator/diff", {
      method: "POST",
      body: JSON.stringify({
        sinceTime: 0,
        limit: 500,
      }),
    });
  }
}

// Types for authenticator endpoints
export interface AuthenticatorKey {
  encryptedKey: string;
  error?: string;
}

export interface AuthenticatorCode {
  id: string;
  data: string;
  header: string;
  isDeleted: boolean;
}

export const api = new ApiService();
