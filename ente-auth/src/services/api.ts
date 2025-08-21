import axios, { AxiosInstance, AxiosError } from 'axios';
import { AuthorizationResponse, AuthKey, AuthEntity } from '../types';
import { getStorageService } from './storage';

const API_BASE_URL = 'https://api.ente.io';

export class EnteApiClient {
  private client: AxiosInstance;

  constructor(token?: string) {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Package': 'io.ente.auth',
        ...(token && { 'X-Auth-Token': token }),
      },
    });

    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        const url = error.config?.url;
        console.error(`API Error on ${url}:`, {
          status: error.response?.status,
          data: error.response?.data,
        });

        if (error.response) {
          switch (error.response.status) {
            case 401:
              error.message = "Authentication failed. Your session may have expired or credentials may be incorrect.";
              break;
            case 404:
              error.message = "The requested resource was not found.";
              break;
            default:
              error.message = "An API error occurred. Please try again later.";
          }
        } else if (error.request) {
          error.message = "Network error. Please check your connection.";
        }
        return Promise.reject(error);
      },
    );
  }

  setToken(token: string): void {
    this.client.defaults.headers.common['X-Auth-Token'] = token;
  }

  async requestEmailOTP(email: string): Promise<void> {
    await this.client.post('/users/ott', { email, purpose: 'login' });
  }

  async verifyEmailOTP(email: string, otp: string): Promise<AuthorizationResponse> {
    const response = await this.client.post('/users/verify-email', { email, ott: otp });
    return response.data;
  }

  async getAuthKey(): Promise<AuthKey> {
    try {
      const response = await this.client.get('/authenticator/key');
      return response.data;
    } catch (error) {
       if ((error as AxiosError).response?.status === 404) {
        throw new Error('AuthenticatorKeyNotFound');
      }
      throw error;
    }
  }

  async createAuthKey(encryptedKey: string, header: string): Promise<AuthKey> {
    const response = await this.client.post('/authenticator/key', { encryptedKey, header });
    return response.data;
  }

  async getAuthDiff(sinceTime = 0, limit = 500): Promise<{ diff: AuthEntity[] }> {
    const response = await this.client.get('/authenticator/entity/diff', {
      params: { sinceTime, limit },
    });
    return response.data;
  }
}

let apiClientInstance: EnteApiClient | null = null;
export const getApiClient = async (): Promise<EnteApiClient> => {
    if (apiClientInstance) {
        // Ensure the token is up-to-date on subsequent calls after login
        const storage = getStorageService();
        const creds = await storage.getCredentials();
        if (creds?.token) {
            apiClientInstance.setToken(creds.token);
        }
        return apiClientInstance;
    }
    const storage = getStorageService();
    const creds = await storage.getCredentials();
    apiClientInstance = new EnteApiClient(creds?.token);
    return apiClientInstance;
};