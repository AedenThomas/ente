import { TokenManager } from './token';
import { api } from '../services/api';
import { Session, SessionState } from '../types/auth';

export class SessionManager {
  private tokenManager: TokenManager;

  constructor() {
    this.tokenManager = new TokenManager();
  }

  async getCurrentSession(): Promise<Session | null> {
    const token = await this.tokenManager.getToken();
    if (!token) {
      return null;
    }

    try {
      const userId = await this.tokenManager.getUserId();
      if (!userId) {
        return null;
      }

      // Verify token is still valid
      await api.verifySession(token.token);

      return {
        userId,
        token: token.token,
        state: SessionState.ACTIVE,
      };
    } catch (error) {
      if (error.status === 401) {
        await this.tokenManager.clearToken();
        return null;
      }
      throw error;
    }
  }

  async logout(): Promise<void> {
    const token = await this.tokenManager.getToken();
    if (token) {
      try {
        await api.logout(token.token);
      } finally {
        await this.tokenManager.clearToken();
      }
    }
  }

  async refreshSession(): Promise<Session | null> {
    const currentSession = await this.getCurrentSession();
    if (!currentSession) {
      return null;
    }

    try {
      const newToken = await api.refreshToken(currentSession.token);
      await this.tokenManager.saveToken(newToken);

      return {
        ...currentSession,
        token: newToken.token,
      };
    } catch (error) {
      await this.tokenManager.clearToken();
      return null;
    }
  }

  async isSessionValid(): Promise<boolean> {
    const session = await this.getCurrentSession();
    return session !== null;
  }
} 