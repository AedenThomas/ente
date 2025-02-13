import { deriveArgonKey, deriveLoginKey } from "../utils/crypto";
import { api } from "../services/api";
import { SRPAttributes, SRPSession, EmailOTPResponse } from "../types/auth";
import { Buffer } from "buffer";
import { SRP, SrpClient } from "fast-srp-hap";

const SRP_PARAMS = SRP.params["4096"];

export class SRPAuth {
  async getSRPAttributes(email: string): Promise<SRPAttributes> {
    console.log("Getting SRP attributes for email:", email);
    const attributes = await api.getSRPAttributes(email);
    console.log("Received SRP attributes:", attributes);
    return attributes;
  }

  async login(email: string, password: string): Promise<SRPSession> {
    try {
      console.log("Starting SRP login process for email:", email);

      // Get SRP attributes for the user
      const srpAttributes = await this.getSRPAttributes(email);
      console.log("Retrieved SRP attributes:", srpAttributes);

      // If email MFA is enabled, we need to send an OTP
      if (srpAttributes.isEmailMFAEnabled) {
        console.log("Email MFA is enabled, sending OTP");
        await api.sendEmailOTP(email);
        throw new Error("EMAIL_MFA_REQUIRED");
      }

      // Derive key encryption key using Argon2
      console.log("Deriving key encryption key with params:", {
        memLimit: srpAttributes.memLimit,
        opsLimit: srpAttributes.opsLimit,
        kekSalt: srpAttributes.kekSalt,
      });

      const keyEncKey = await deriveArgonKey(
        password,
        srpAttributes.kekSalt,
        srpAttributes.memLimit,
        srpAttributes.opsLimit,
      );
      console.log("Key encryption key derived successfully");

      // Generate login key
      console.log("Generating login key");
      const loginKey = await deriveLoginKey(keyEncKey);
      console.log("Login key generated successfully");

      // Generate SRP client
      const srpClient = await new Promise<SrpClient>((resolve, reject) => {
        SRP.genKey((err, secret) => {
          if (err) {
            reject(err);
            return;
          }
          if (!secret) {
            reject(new Error("Failed to generate SRP secret"));
            return;
          }
          const client = new SrpClient(
            SRP_PARAMS,
            Buffer.from(srpAttributes.srpSalt, "base64"),
            Buffer.from(srpAttributes.srpUserID),
            Buffer.from(loginKey),
            secret,
            false,
          );
          resolve(client);
        });
      });

      // Calculate A
      const A = srpClient.computeA();
      console.log("Generated A value:", A.toString("base64"));

      // Create SRP session
      const session = await api.createSRPSession(srpAttributes.srpUserID, A.toString("base64"));
      console.log("SRP session created:", session);

      // Set B and calculate M1
      srpClient.setB(Buffer.from(session.srpB, "base64"));
      const M1 = srpClient.computeM1();
      console.log("Calculated M1:", M1.toString("base64"));

      // Verify SRP session
      const authResponse = await api.verifySRPSession(
        srpAttributes.srpUserID,
        session.sessionID,
        M1.toString("base64"),
      );

      // Verify M2
      if (authResponse.srpM2) {
        srpClient.checkM2(Buffer.from(authResponse.srpM2, "base64"));
      }

      console.log("SRP session verified successfully");

      return {
        ...authResponse,
        keyEncKey,
      };
    } catch (error) {
      console.error("SRP login failed:", error);
      throw error;
    }
  }

  async verifyEmailOTP(email: string, otp: string): Promise<EmailOTPResponse> {
    try {
      console.log("Verifying email OTP");
      const response = await api.verifyEmailOTP(email, otp);
      console.log("Email OTP verified successfully");
      return response;
    } catch (error) {
      console.error("Email OTP verification failed:", error);
      throw error;
    }
  }
}
