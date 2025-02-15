import { deriveArgonKey, deriveLoginKey, padBuffer } from "../utils/crypto";
import { api } from "../services/api";
import { SRPAttributes, SRPSession, EmailOTPResponse, Token } from "../types/auth";
import { TokenManager } from "./token";
import { Buffer } from "buffer";
import { SRP, SrpClient } from "fast-srp-hap";
import { showToast, Toast, LocalStorage } from "@raycast/api";
import { debugLog } from "../utils/logger";

const SRP_PARAMS = SRP.params["4096"];

const STORAGE_KEYS = {
  SRP_ATTRIBUTES: "srp_attributes",
  EMAIL: "stored_email",
  PASSWORD: "stored_password",
};

// Add helper functions
function convertBufferToBase64(buffer: Buffer): string {
  return buffer.toString("base64");
}

function convertBase64ToBuffer(base64: string): Buffer {
  return Buffer.from(base64, "base64");
}

async function generateSRPClient(srpSalt: string, srpUserID: string, loginKey: Buffer): Promise<SrpClient> {
  return new Promise<SrpClient>((resolve, reject) => {
    SRP.genKey((err, secret) => {
      try {
        if (err) {
          console.error("[generateSRPClient] Failed to generate secret:", err);
          reject(err);
          return;
        }
        if (!secret) {
          console.error("[generateSRPClient] Generated secret is null");
          reject(new Error("Failed to generate SRP secret"));
          return;
        }

        console.log("[generateSRPClient] Generated secret:", {
          length: secret.length,
          firstBytes: Array.from(secret.slice(0, 5)),
          base64: secret.toString("base64"),
        });

        const client = new SrpClient(
          SRP_PARAMS,
          convertBase64ToBuffer(srpSalt),
          Buffer.from(srpUserID),
          loginKey,
          secret,
          false
        );

        console.log("[generateSRPClient] Created SRP client with params:", {
          saltLength: srpSalt.length,
          userIDLength: srpUserID.length,
          loginKeyLength: loginKey.length,
          secretLength: secret.length,
          saltFirstBytes: Array.from(convertBase64ToBuffer(srpSalt).slice(0, 5)),
          loginKeyFirstBytes: Array.from(loginKey.slice(0, 5)),
          secretFirstBytes: Array.from(secret.slice(0, 5)),
        });

        resolve(client);
      } catch (error) {
        console.error("[generateSRPClient] Failed to create SRP client:", {
          error: error instanceof Error ? error.message : "Unknown error",
          stack: error instanceof Error ? error.stack : undefined,
        });
        reject(error);
      }
    });
  });
}

export class SRPAuth {
  private tokenManager: TokenManager;

  constructor(tokenManager: TokenManager) {
    this.tokenManager = tokenManager;
    console.log("[SRPAuth] Initialized new SRPAuth instance");
    debugLog("[SRPAuth] Debugging initiated for SRPAuth instance", tokenManager);
  }

  private async saveState(email: string, password: string, srpAttributes: SRPAttributes) {
    console.log("[SRPAuth.saveState] Saving authentication state");
    await LocalStorage.setItem(STORAGE_KEYS.EMAIL, email);
    await LocalStorage.setItem(STORAGE_KEYS.PASSWORD, password);
    await LocalStorage.setItem(STORAGE_KEYS.SRP_ATTRIBUTES, JSON.stringify(srpAttributes));
  }

  private async clearState() {
    console.log("[SRPAuth.clearState] Clearing authentication state");
    await LocalStorage.removeItem(STORAGE_KEYS.EMAIL);
    await LocalStorage.removeItem(STORAGE_KEYS.PASSWORD);
    await LocalStorage.removeItem(STORAGE_KEYS.SRP_ATTRIBUTES);
  }

  private async getStoredState(): Promise<{ email?: string; password?: string; srpAttributes?: SRPAttributes }> {
    const email = await LocalStorage.getItem<string>(STORAGE_KEYS.EMAIL);
    const password = await LocalStorage.getItem<string>(STORAGE_KEYS.PASSWORD);
    const srpAttributesStr = await LocalStorage.getItem<string>(STORAGE_KEYS.SRP_ATTRIBUTES);

    const srpAttributes = srpAttributesStr ? JSON.parse(srpAttributesStr) : undefined;

    console.log("[SRPAuth.getStoredState] Retrieved state:", {
      hasEmail: !!email,
      hasPassword: !!password,
      hasSrpAttributes: !!srpAttributes,
    });

    return {
      email: email || undefined,
      password: password || undefined,
      srpAttributes,
    };
  }

  async login(email: string, password: string): Promise<SRPSession> {
    try {
      console.log("[SRPAuth.login] Starting SRP login process");

      // Get SRP attributes for the user
      const srpAttributes = await this.getSRPAttributes(email);
      console.log("[SRPAuth.login] Retrieved SRP attributes:", {
        srpUserID: srpAttributes.srpUserID,
        memLimit: srpAttributes.memLimit,
        opsLimit: srpAttributes.opsLimit,
        isEmailMFAEnabled: srpAttributes.isEmailMFAEnabled,
      });

      // Save state for potential reuse after OTP
      await this.saveState(email, password, srpAttributes);

      // Derive key encryption key using Argon2
      console.log("[SRPAuth.login] Starting key derivation");
      const keyEncKey = await deriveArgonKey(
        password,
        srpAttributes.kekSalt,
        srpAttributes.memLimit,
        srpAttributes.opsLimit
      );
      console.log("[SRPAuth.login] Key encryption key derived successfully, length:", keyEncKey.length);

      // Save the master key for token decryption later
      await this.tokenManager.saveMasterKey(keyEncKey);
      console.log("[SRPAuth.login] Master key saved to token manager");

      // If email MFA is enabled, we need to send an OTP
      if (srpAttributes.isEmailMFAEnabled) {
        console.log("[SRPAuth.login] Email MFA required, sending OTP");
        try {
          await api.sendEmailOTP(email);
          await showToast({
            style: Toast.Style.Success,
            title: "OTP Sent",
            message: "Please check your email for the verification code",
          });
        } catch (error) {
          console.error("[SRPAuth.login] Failed to send OTP:", error);
          await showToast({
            style: Toast.Style.Failure,
            title: "Failed to Send OTP",
            message: "Please try again",
          });
          await this.clearState();
          throw error;
        }
        throw new Error("EMAIL_MFA_REQUIRED");
      }

      // Complete SRP login
      return this.completeSRPLogin(srpAttributes, keyEncKey);
    } catch (error) {
      console.error("[SRPAuth.login] Login failed:", error);
      throw error;
    }
  }

  private async completeSRPLogin(srpAttributes: SRPAttributes, keyEncKey: Uint8Array): Promise<SRPSession> {
    try {
      console.log("[SRPAuth.completeSRPLogin] Starting SRP login completion with attributes:", {
        srpUserID: srpAttributes.srpUserID,
        srpSaltLength: srpAttributes.srpSalt?.length,
        memLimit: srpAttributes.memLimit,
        opsLimit: srpAttributes.opsLimit,
        keyEncKeyLength: keyEncKey.length,
        keyEncKeyFirstBytes: Array.from(keyEncKey.slice(0, 5)),
      });

      // Generate login key
      console.log("[SRPAuth.completeSRPLogin] Generating login key");
      const loginKey = await deriveLoginKey(keyEncKey);
      console.log("[SRPAuth.completeSRPLogin] Login key generated:", {
        length: loginKey.length,
        firstBytes: Array.from(loginKey.slice(0, 5)),
        isBuffer: loginKey instanceof Buffer,
        type: Object.prototype.toString.call(loginKey),
        base64: Buffer.from(loginKey).toString("base64"),
      });

      // Convert login key to Buffer
      const loginKeyBuffer = Buffer.from(loginKey);
      console.log("[SRPAuth.completeSRPLogin] Login key converted to Buffer:", {
        length: loginKeyBuffer.length,
        firstBytes: Array.from(loginKeyBuffer.slice(0, 5)),
        isBuffer: loginKeyBuffer instanceof Buffer,
        type: Object.prototype.toString.call(loginKeyBuffer),
        equals: Buffer.compare(loginKey, loginKeyBuffer) === 0,
        base64: loginKeyBuffer.toString("base64"),
      });

      // Create SRP client
      console.log("[SRPAuth.completeSRPLogin] Generating SRP client with params:", {
        saltLength: srpAttributes.srpSalt?.length,
        userIdLength: srpAttributes.srpUserID?.length,
        loginKeyLength: loginKeyBuffer.length,
        srpSaltFirstBytes: Array.from(convertBase64ToBuffer(srpAttributes.srpSalt).slice(0, 5)),
        srpUserIDFirstBytes: Array.from(Buffer.from(srpAttributes.srpUserID).slice(0, 5)),
        srpSaltBase64: srpAttributes.srpSalt,
      });

      const srpClient = await generateSRPClient(srpAttributes.srpSalt, srpAttributes.srpUserID, loginKeyBuffer);

      // Generate A value
      const A = srpClient.computeA();
      console.log("[SRPAuth.completeSRPLogin] Generated A value:", {
        length: A.length,
        firstBytes: Array.from(A.slice(0, 5)),
        base64: convertBufferToBase64(A),
        isBuffer: A instanceof Buffer,
        type: Object.prototype.toString.call(A),
      });

      // Create session
      const session = await api.createSRPSession(srpAttributes.srpUserID, convertBufferToBase64(A));

      console.log("[SRPAuth.completeSRPLogin] SRP session created:", {
        sessionID: session.sessionID,
        hasSrpB: !!session.srpB,
        srpBLength: session.srpB?.length,
        srpBFirstBytes: session.srpB ? Array.from(convertBase64ToBuffer(session.srpB).slice(0, 5)) : null,
      });

      // Set B value
      const B = convertBase64ToBuffer(session.srpB);
      console.log("[SRPAuth.completeSRPLogin] Setting B value:", {
        length: B.length,
        firstBytes: Array.from(B.slice(0, 5)),
        base64: session.srpB,
        isBuffer: B instanceof Buffer,
        type: Object.prototype.toString.call(B),
      });

      srpClient.setB(B);

      // Calculate M1
      const M1 = srpClient.computeM1();
      console.log("[SRPAuth.completeSRPLogin] Calculated M1:", {
        length: M1.length,
        firstBytes: Array.from(M1.slice(0, 5)),
        base64: convertBufferToBase64(M1),
        isBuffer: M1 instanceof Buffer,
        type: Object.prototype.toString.call(M1),
        rawBuffer: M1.toString("hex"),
      });

      // Send M1 without additional base64 encoding
      console.log("[SRPAuth.completeSRPLogin] Verifying SRP session with:", {
        srpUserID: srpAttributes.srpUserID,
        sessionID: session.sessionID,
        m1Length: M1.length,
        m1Base64: convertBufferToBase64(M1),
        m1Hex: M1.toString("hex"),
        requestOrder: {
          first: "sessionID",
          second: "srpUserID",
          third: "srpM1",
        },
      });

      const verificationResponse = await api.verifySRPSession(
        session.sessionID,
        srpAttributes.srpUserID,
        convertBufferToBase64(M1)
      );

      console.log("[SRPAuth.completeSRPLogin] Session verification response:", {
        hasResponse: !!verificationResponse,
        id: verificationResponse.id,
        hasKeyAttributes: !!verificationResponse.keyAttributes,
        hasEncryptedToken: !!verificationResponse.encryptedToken,
        hasM2: !!verificationResponse.srpM2,
        m2Length: verificationResponse.srpM2?.length,
        m2FirstChars: verificationResponse.srpM2 ? verificationResponse.srpM2.substring(0, 10) : null,
      });

      // Verify M2
      if (verificationResponse.srpM2) {
        const M2 = convertBase64ToBuffer(verificationResponse.srpM2);
        console.log("[SRPAuth.completeSRPLogin] Verifying M2:", {
          m2Length: M2.length,
          m2FirstBytes: Array.from(M2.slice(0, 5)),
          m2Base64: verificationResponse.srpM2,
          m2Hex: M2.toString("hex"),
        });

        srpClient.checkM2(M2);
        console.log("[SRPAuth.completeSRPLogin] M2 verification successful");
      } else {
        console.warn("[SRPAuth.completeSRPLogin] No M2 value in response");
      }

      return {
        id: verificationResponse.id,
        keyAttributes: verificationResponse.keyAttributes,
        encryptedToken: verificationResponse.encryptedToken,
        srpM2: verificationResponse.srpM2,
      };
    } catch (error) {
      console.error("[SRPAuth.completeSRPLogin] SRP login failed:", {
        error: error instanceof Error ? error.message : "Unknown error",
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  async getSRPAttributes(email: string): Promise<SRPAttributes> {
    console.log("[SRPAuth.getSRPAttributes] Getting SRP attributes for email");
    const attributes = await api.getSRPAttributes(email);
    console.log("[SRPAuth.getSRPAttributes] Retrieved attributes:", {
      srpUserID: attributes.srpUserID,
      memLimit: attributes.memLimit,
      opsLimit: attributes.opsLimit,
      isEmailMFAEnabled: attributes.isEmailMFAEnabled,
    });
    return attributes;
  }

  async verifyEmailOTP(email: string, otp: string): Promise<EmailOTPResponse> {
    console.log("[SRPAuth.verifyEmailOTP] Starting email OTP verification");

    try {
      // Get stored state
      const state = await this.getStoredState();
      console.log("[SRPAuth.verifyEmailOTP] Retrieved state:", {
        hasEmail: !!state.email,
        hasPassword: !!state.password,
        hasSrpAttributes: !!state.srpAttributes,
      });

      if (!state.email || !state.password || !state.srpAttributes) {
        throw new Error("Authentication state not found. Please try logging in again.");
      }

      // Verify email matches
      if (email !== state.email) {
        throw new Error("Email mismatch. Please try logging in again.");
      }

      // Verify OTP
      const response = await api.verifyEmailOTP(email, otp);
      console.log("[SRPAuth.verifyEmailOTP] OTP verified successfully");
      console.log("[SRPAuth.verifyEmailOTP] Response:", {
        id: response.id,
        hasKeyAttributes: !!response.keyAttributes,
        hasEncryptedToken: !!response.encryptedToken,
      });

      await showToast({
        style: Toast.Style.Success,
        title: "OTP Verified",
        message: "Login successful",
      });

      // Re-derive key encryption key
      console.log("[SRPAuth.verifyEmailOTP] Re-deriving key encryption key");
      const keyEncKey = await deriveArgonKey(
        state.password,
        state.srpAttributes.kekSalt,
        state.srpAttributes.memLimit,
        state.srpAttributes.opsLimit
      );
      await this.tokenManager.saveMasterKey(keyEncKey);

      // Save the token
      await this.tokenManager.saveToken(response);

      // Clear stored state
      await this.clearState();

      // Cast response to EmailOTPResponse
      const emailOTPResponse: EmailOTPResponse = {
        id: response.id,
        keyAttributes: response.keyAttributes!,
        encryptedToken: response.encryptedToken,
        passkeySessionID: response.passkeySessionID,
      };

      return emailOTPResponse;
    } catch (error) {
      console.error("[SRPAuth.verifyEmailOTP] OTP verification failed:", error);
      throw error;
    }
  }
}
