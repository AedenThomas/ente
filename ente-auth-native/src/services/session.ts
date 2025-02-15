import { LocalStorage } from "@raycast/api";

export class SessionManager {
  private static readonly TOKEN_KEY = "auth_token";

  async getToken(): Promise<string | undefined> {
    return LocalStorage.getItem(SessionManager.TOKEN_KEY);
  }

  async logout(): Promise<void> {
    await LocalStorage.removeItem(SessionManager.TOKEN_KEY);
  }
}
