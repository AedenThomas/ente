import { deriveArgonKey, deriveLoginKey } from "../utils/crypto";
import { api } from "../services/api";
import { SRPAttributes, SRPSession, EmailOTPResponse } from "../types/auth";
import { TokenManager } from "./token";
import { Buffer } from "buffer";
import { SRP, SrpClient } from "fast-srp-hap";
import { showToast, Toast, LocalStorage } from "@raycast/api";

const SRP_PARAMS = SRP.params["4096"];

const STORAGE_KEYS = {
  SRP_ATTRIBUTES: "srp_attributes",
  EMAIL: "stored_email",
  PASSWORD: "stored_password",
};

export class SRPAuth {
  private tokenManager: TokenManager;

  constructor(tokenManager: TokenManager) {
    this.tokenManager = tokenManager;
    console.log("[SRPAuth] Initialized new SRPAuth instance");
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
    const email = await LocalStorage.getItem(STORAGE_KEYS.EMAIL);
    const password = await LocalStorage.getItem(STORAGE_KEYS.PASSWORD);
    const srpAttributesStr = await LocalStorage.getItem(STORAGE_KEYS.SRP_ATTRIBUTES);

    const srpAttributes = srpAttributesStr ? JSON.parse(srpAttributesStr) : undefined;

    console.log("[SRPAuth.getStoredState] Retrieved state:", {
      hasEmail: !!email,
      hasPassword: !!password,
      hasSrpAttributes: !!srpAttributes,
    });

    return { email, password, srpAttributes };
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
        }
        throw new Error("EMAIL_MFA_REQUIRED");
      }

      console.log("[SRPAuth.login] No MFA required, proceeding with SRP login");
      const result = await this.completeSRPLogin(srpAttributes, keyEncKey);
      await this.clearState();
      return result;
    } catch (error) {
      if (error.message !== "EMAIL_MFA_REQUIRED") {
        await this.clearState();
        console.error("[SRPAuth.login] SRP login failed with non-MFA error:", error);
      }
      throw error;
    }
  }

  private async completeSRPLogin(srpAttributes: SRPAttributes, keyEncKey: Uint8Array): Promise<SRPSession> {
    console.log("[SRPAuth.completeSRPLogin] Starting SRP login completion");

    // Generate login key
    console.log("[SRPAuth.completeSRPLogin] Generating login key");
    const loginKey = await deriveLoginKey(keyEncKey);
    console.log("[SRPAuth.completeSRPLogin] Login key generated, length:", loginKey.length);

    // Generate SRP client
    console.log("[SRPAuth.completeSRPLogin] Generating SRP client");
    const srpClient = await new Promise<SrpClient>((resolve, reject) => {
      SRP.genKey((err, secret) => {
        if (err) {
          console.error("[SRPAuth.completeSRPLogin] Failed to generate SRP secret:", err);
          reject(err);
          return;
        }
        if (!secret) {
          console.error("[SRPAuth.completeSRPLogin] SRP secret generation returned null");
          reject(new Error("Failed to generate SRP secret"));
          return;
        }
        const client = new SrpClient(
          SRP_PARAMS,
          Buffer.from(srpAttributes.srpSalt, "base64"),
          Buffer.from(srpAttributes.srpUserID),
          Buffer.from(loginKey),
          secret,
          false
        );
        console.log("[SRPAuth.completeSRPLogin] SRP client created successfully");
        resolve(client);
      });
    });

    // Calculate A
    const A = srpClient.computeA();
    console.log("[SRPAuth.completeSRPLogin] Generated A value, length:", A.length);

    // Create SRP session
    const session = await api.createSRPSession(srpAttributes.srpUserID, A.toString("base64"));
    console.log("[SRPAuth.completeSRPLogin] SRP session created:", {
      sessionID: session.sessionID,
      hasSrpB: !!session.srpB,
    });

    // Set B and calculate M1
    srpClient.setB(Buffer.from(session.srpB, "base64"));
    const M1 = srpClient.computeM1();
    console.log("[SRPAuth.completeSRPLogin] Calculated M1, length:", M1.length);

    // Verify SRP session
    const authResponse = await api.verifySRPSession(srpAttributes.srpUserID, session.sessionID, M1.toString("base64"));
    console.log("[SRPAuth.completeSRPLogin] SRP session verified:", {
      hasSrpM2: !!authResponse.srpM2,
      hasKeyAttributes: !!authResponse.keyAttributes,
      hasEncryptedToken: !!authResponse.encryptedToken,
    });

    // Verify M2
    if (authResponse.srpM2) {
      srpClient.checkM2(Buffer.from(authResponse.srpM2, "base64"));
      console.log("[SRPAuth.completeSRPLogin] M2 verification successful");
    }

    console.log("[SRPAuth.completeSRPLogin] SRP login completed successfully");
    return authResponse;
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
      const { email: storedEmail, password, srpAttributes } = await this.getStoredState();

      if (!storedEmail || !password || !srpAttributes) {
        throw new Error("Authentication state not found. Please try logging in again.");
      }

      // Verify email matches
      if (email !== storedEmail) {
        throw new Error("Email mismatch. Please try logging in again.");
      }

      // Verify OTP
      const response = await api.verifyEmailOTP(email, otp);
      console.log("[SRPAuth.verifyEmailOTP] OTP verified successfully");
      await showToast({
        style: Toast.Style.Success,
        title: "OTP Verified",
        message: "Login successful",
      });

      // Derive key encryption key again
      console.log("[SRPAuth.verifyEmailOTP] Re-deriving key encryption key");
      const keyEncKey = await deriveArgonKey(
        password,
        srpAttributes.kekSalt,
        srpAttributes.memLimit,
        srpAttributes.opsLimit
      );
      await this.tokenManager.saveMasterKey(keyEncKey);

      // Save and decrypt the token
      await this.tokenManager.saveToken(response.keyAttributes, response.encryptedToken);

      // Clear stored state after successful login
      await this.clearState();

      return response;
    } catch (error) {
      console.error("[SRPAuth.verifyEmailOTP] OTP verification failed:", error);
      await this.clearState();

      let errorMessage = "Please try again";
      if (error.response?.status === 401) {
        errorMessage = "Incorrect verification code";
      } else {
        errorMessage = error.message || errorMessage;
      }

      await showToast({
        style: Toast.Style.Failure,
        title: "Invalid OTP",
        message: errorMessage,
      });
      throw error;
    }
  }
}
