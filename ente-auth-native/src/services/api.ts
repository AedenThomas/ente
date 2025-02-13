import { environment } from "../config/environment";
import { AuthError, PasskeySession, PasskeyVerificationResult, SRPAttributes, Token, TokenInfo } from "../types/auth";
import { open } from "@raycast/api";
import fetch from "node-fetch";
import type { RequestInit } from "node-fetch";

class ApiService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = environment.apiUrl;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    console.log(`Making request to: ${url}`);
    console.log("Request options:", JSON.stringify(options, null, 2));

    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    const responseText = await response.text();
    console.log("Response status:", response.status);
    console.log("Response text:", responseText);

    if (!response.ok) {
      try {
        const error = JSON.parse(responseText) as AuthError;
        error.status = response.status;

        // For SESSION_NOT_VERIFIED, we want to throw the parsed error object
        if (error.code === "SESSION_NOT_VERIFIED") {
          throw error;
        }

        // For other passkey verification errors, throw with status
        if (response.status === 404 || response.status === 409 || response.status === 410) {
          error.status = response.status;
          throw error;
        }

        throw new Error(`Request failed: ${response.status} ${responseText}`);
      } catch (e) {
        // If the error is already properly formatted (has code property), rethrow it
        if (e instanceof Error && "code" in e) {
          throw e;
        }
        throw new Error(`Request failed: ${response.status} ${responseText}`);
      }
    }

    // If response is empty and status is OK, return empty object
    if (!responseText && response.ok) {
      return {} as T;
    }

    try {
      return JSON.parse(responseText);
    } catch (e) {
      throw new Error(`Invalid JSON response: ${responseText}`);
    }
  }

  async getSRPAttributes(email: string): Promise<SRPAttributes> {
    const response = await this.request<{ attributes: SRPAttributes }>(
      `/users/srp/attributes?email=${encodeURIComponent(email)}`,
    );
    return response.attributes;
  }

  async createSRPSession(srpUserID: string, srpA: string): Promise<{ sessionID: string; srpB: string }> {
    return this.request("/users/srp/create-session", {
      method: "POST",
      body: JSON.stringify({ srpUserID, srpA }),
    });
  }

  async verifySRPSession(srpUserID: string, sessionID: string, srpM1: string): Promise<Token> {
    return this.request("/users/srp/verify-session", {
      method: "POST",
      body: JSON.stringify({ srpUserID, sessionID, srpM1 }),
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

  async verifySession(token: string): Promise<void> {
    return this.request("/users/verify-session", {
      headers: {
        "X-Auth-Token": token,
      },
    });
  }

  async logout(token: string): Promise<void> {
    return this.request("/users/logout", {
      method: "POST",
      headers: {
        "X-Auth-Token": token,
      },
    });
  }

  async refreshToken(token: string): Promise<Token> {
    return this.request("/users/refresh-token", {
      method: "POST",
      headers: {
        "X-Auth-Token": token,
      },
    });
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
}

export const api = new ApiService();
