import { TokenManager } from "./token";

export class SessionManager {
  private tokenManager: TokenManager;

  constructor() {
    this.tokenManager = new TokenManager();
  }

  async getToken(): Promise<string | undefined> {
    return this.tokenManager.getToken();
  }

  async logout(): Promise<void> {
    await this.tokenManager.clearToken();
  }
} 