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
  masterKeyEncryptedWithRecoveryKey?: string;
  masterKeyDecryptionNonce?: string;
  recoveryKeyEncryptedWithMasterKey?: string;
  recoveryKeyDecryptionNonce?: string;
}

export interface SRPSession extends Token {
  srpM2: string;
}

export interface Token {
  id: string;
  keyAttributes?: KeyAttributes;
  encryptedToken: string;
  token?: string;
  twoFactorSessionID?: string;
  passkeySessionID?: string;
  srpM2?: string;
}

export interface TokenInfo {
  id: string;
  createdAt: string;
  lastUsedAt: string;
  deviceInfo: {
    name: string;
    os: string;
    browser: string;
  };
  current: boolean;
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
  id: string;
  keyAttributes: KeyAttributes;
  encryptedToken: string;
}

export interface TokenRefreshResponse {
  id: number;
  keyAttributes: {
    kekSalt: string;
    kekHash: string;
    encryptedKey: string;
    keyDecryptionNonce: string;
    publicKey: string;
    encryptedSecretKey: string;
    secretKeyDecryptionNonce: string;
    memLimit: number;
    opsLimit: number;
    masterKeyEncryptedWithRecoveryKey?: string;
    masterKeyDecryptionNonce?: string;
    recoveryKeyEncryptedWithMasterKey?: string;
    recoveryKeyDecryptionNonce?: string;
  };
  encryptedToken: string;
  hasSetKeys?: boolean;
  twoFactorSessionID?: string;
  twoFactorSessionIDV2?: string;
  passkeySessionID?: string;
  accountsUrl?: string;
}
