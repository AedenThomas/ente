export interface SRPAttributes {
  srpUserID: string;
  srpSalt: string;
  memLimit: number;
  opsLimit: number;
  kekSalt: string;
  isEmailMFAEnabled: boolean;
}

export interface KeyAttributes {
  kekSalt: string;
  kekHash: string;
  encryptedKey: string;
  keyDecryptionNonce: string;
  publicKey: string;
  encryptedSecretKey: string;
  secretKeyDecryptionNonce: string;
  memLimit: number;
  opsLimit: number;
}

export interface SRPSession extends Token {
  srpM2: string;
}

export interface Token {
  token: string;
  encryptedToken: string;
  keyAttributes?: KeyAttributes;
  id: string;
}

export interface TokenInfo {
  creationTime: number;
  lastUsedTime: number;
  userAgent: string;
  isDeleted: boolean;
  app: string;
}

export interface PasskeySession {
  ceremonySessionID: string;
  options: {
    publicKey: PublicKeyCredentialRequestOptions;
  };
}

export interface PasskeyVerificationResult extends Token {
  passkeySessionID?: string;
  accountsUrl?: string;
}

export interface Session {
  userId: string;
  token: string;
  state: SessionState;
}

export enum SessionState {
  ACTIVE = "active",
  EXPIRED = "expired",
  INVALID = "invalid",
}

export interface AuthError {
  code: string;
  message: string;
  status?: number;
}

export interface EmailOTPResponse extends Token {
  passkeySessionID?: string;
  accountsUrl?: string;
  twoFactorSessionID?: string;
}
