export interface AuthKey {
  userID: number;
  encryptedKey: string;
  header: string;
}

export interface AuthEntity {
  id: string;
  encryptedData: string | null;
  header: string | null;
  isDeleted: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface AuthData {
  id: string;
  name: string;
  issuer?: string;
  secret: string;
  type: 'totp' | 'hotp' | 'steam';
  algorithm: 'sha1' | 'sha256' | 'sha512';
  digits: number;
  period: number;
  counter?: number;
  updatedAt: number;
}

export interface AuthCode extends AuthData {
  code: string;
  remainingSeconds?: number;
  progress?: number;
}

export interface UserCredentials {
  email: string;
  token: string;
  masterKey: Uint8Array;
  keyAttributes: KeyAttributes;
}

// This interface now matches the Go struct perfectly.
export interface KeyAttributes {
  kekSalt: string;
  encryptedKey: string;
  keyDecryptionNonce: string;
  encryptedSecretKey: string;
  secretKeyDecryptionNonce: string;
  memLimit: number;
  opsLimit: number;
}

export interface AuthorizationResponse {
  id: number;
  encryptedToken: string;
  keyAttributes: KeyAttributes;
}