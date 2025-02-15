import { environment } from "../config/environment";
import { PasskeySession, PasskeyVerificationResult, SRPAttributes, Token, TokenInfo } from "../types/auth";
import { open } from "@raycast/api";
import fetch, { Headers } from "node-fetch";
import type { RequestInit } from "node-fetch";
import { SessionManager } from "../auth/session";
import { TokenManager, TokenResponse } from "../auth/token";

type CustomHeaders = Record<string, string>;

// Add SRPSession type
interface SRPSession {
  id: string;
  keyAttributes: {
    encryptedKey: string;
    keyDecryptionNonce: string;
    encryptedSecretKey: string;
    secretKeyDecryptionNonce: string;
    publicKey: string;
  };
  encryptedToken: string;
  srpM2: string;
}

export class ApiService {
  private baseUrl: string;
  private sessionManager: SessionManager;
  private tokenManager: TokenManager;

  constructor(baseUrl: string, sessionManager: SessionManager, tokenManager: TokenManager) {
    this.baseUrl = baseUrl;
    this.sessionManager = sessionManager;
    this.tokenManager = tokenManager;
  }

  private async getAuthHeaders(): Promise<CustomHeaders> {
    const token = await this.tokenManager.getToken();
    const headers: CustomHeaders = {
      "Content-Type": "application/json",
    };

    if (token) {
      headers["X-Auth-Token"] = token;
    }

    return headers;
  }

  async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    console.log(`[API.request] Making request to: ${this.baseUrl}${endpoint}`);

    const currentToken = await this.tokenManager.getToken();
    console.debug("[API.request] Current token state:", {
      hasToken: !!currentToken,
      tokenLength: currentToken?.length,
      endpoint,
      method: options.method,
      isRefreshRequest: endpoint.includes("/session-refresh"),
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
        headers: new Headers({
          ...headers,
          ...(options.headers || {}),
        }),
      });

      const text = await response.text();

      if (!response.ok) {
        if (response.status === 401 && !endpoint.includes("/session-refresh") && currentToken) {
          console.log("[API.request] Got 401, attempting token refresh");
          try {
            await this.refreshToken({ token: currentToken });
            return this.request<T>(endpoint, options);
          } catch (error) {
            console.error("[API.request] Token refresh failed:", error);
            if (error instanceof Error && error.message.includes("401")) {
              await this.tokenManager.clearToken();
            }
          }
        }

        throw new Error(`Request failed: ${response.status} ${text}`);
      }

      if (text && (text.startsWith("{") || text.startsWith("["))) {
        return JSON.parse(text) as T;
      }
      return null as T;
    } catch (error) {
      console.error("[API.request] Request error:", error);
      throw error;
    }
  }

  async refreshToken(params: { token: string }): Promise<TokenResponse> {
    try {
      const response = await fetch(`${this.baseUrl}/users/session/refresh`, {
        method: "POST",
        headers: new Headers({
          "Content-Type": "application/json",
          "X-Auth-Token": params.token,
        }),
      });

      const text = await response.text();
      if (!response.ok) {
        // Clear token on 401 or 404
        if (response.status === 401 || response.status === 404) {
          await this.tokenManager.clearToken();
        }
        throw new Error(`Token refresh failed: ${response.status} ${text}`);
      }

      if (!text) {
        throw new Error("Empty response from refresh token API");
      }

      const data = JSON.parse(text) as TokenResponse;
      if (!data.encryptedToken || !data.keyAttributes) {
        throw new Error("Invalid response from refresh token API");
      }

      await this.tokenManager.saveToken(data);
      return data;
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

    return this.request<SRPSession>("/users/srp/verify-session", {
      method: "POST",
      body: JSON.stringify({
        sessionID,
        srpUserID,
        srpM1,
      }),
    });
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

export const api = new ApiService(environment.apiUrl, new SessionManager(), new TokenManager());
