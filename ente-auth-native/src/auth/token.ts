import { LocalStorage } from '@raycast/api';
import { api } from '../services/api';
import { Token, TokenInfo } from '../types/auth';

export class TokenManager {
  private static readonly TOKEN_KEY = 'auth_token';
  private static readonly USER_ID_KEY = 'user_id';

  async saveToken(token: Token): Promise<void> {
    await LocalStorage.setItem(TokenManager.TOKEN_KEY, JSON.stringify(token));
  }

  async getToken(): Promise<Token | null> {
    const tokenStr = await LocalStorage.getItem(TokenManager.TOKEN_KEY);
    return tokenStr ? JSON.parse(tokenStr) : null;
  }

  async clearToken(): Promise<void> {
    await LocalStorage.removeItem(TokenManager.TOKEN_KEY);
    await LocalStorage.removeItem(TokenManager.USER_ID_KEY);
  }

  async saveUserId(userId: string): Promise<void> {
    await LocalStorage.setItem(TokenManager.USER_ID_KEY, userId);
  }

  async getUserId(): Promise<string | null> {
    return await LocalStorage.getItem(TokenManager.USER_ID_KEY);
  }

  async getActiveSessions(): Promise<TokenInfo[]> {
    const userId = await this.getUserId();
    if (!userId) {
      throw new Error('User ID not found');
    }
    return await api.getActiveSessions(userId);
  }

  async terminateSession(token: string): Promise<void> {
    const userId = await this.getUserId();
    if (!userId) {
      throw new Error('User ID not found');
    }
    await api.terminateSession(userId, token);
  }

  async terminateAllOtherSessions(): Promise<void> {
    const currentToken = await this.getToken();
    if (!currentToken) {
      throw new Error('No active session');
    }
    const userId = await this.getUserId();
    if (!userId) {
      throw new Error('User ID not found');
    }
    await api.terminateAllOtherSessions(userId, currentToken.token);
  }
} 