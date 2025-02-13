import { api } from "../services/api";
import { PasskeyVerificationResult } from "../types/auth";
import { open } from "@raycast/api";
import { environment } from "../config/environment";

// Error messages that match the web implementation
export const passkeySessionExpiredErrorMessage = "Passkey session has expired";
export const passkeySessionAlreadyClaimedErrorMessage = "Passkey session already claimed";

export class PasskeyAuth {
  async verifyPasskey(userId: string, passkeySessionID: string): Promise<PasskeyVerificationResult> {
    try {
      // Construct verification URL in the same format as other clients
      const params = new URLSearchParams({
        passkeySessionID,
        redirect: "extension://ente.auth",
        clientPackage: "io.ente.auth.raycast",
      });
      const verificationUrl = `${environment.accountsUrl}/passkeys/verify?${params.toString()}`;
      console.log("Opening passkey verification URL:", verificationUrl);
      await open(verificationUrl);

      // Poll for verification status
      return await this.pollVerificationStatus(passkeySessionID);
    } catch (error) {
      console.error("Passkey verification failed:", error);
      throw error;
    }
  }

  private async pollVerificationStatus(passkeySessionID: string): Promise<PasskeyVerificationResult> {
    const maxAttempts = 60; // 1 minute with 1-second intervals
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const result = await api.checkPasskeyStatus(passkeySessionID);
        if (result) {
          console.log("Passkey verification successful");
          return result;
        }
      } catch (error: any) {
        // Handle specific error cases like the web implementation
        if (error.status === 404 || error.status === 410) {
          throw new Error(passkeySessionExpiredErrorMessage);
        }
        if (error.status === 409) {
          throw new Error(passkeySessionAlreadyClaimedErrorMessage);
        }
        if (error.code === "SESSION_NOT_VERIFIED") {
          console.log(`Waiting for passkey verification... (attempt ${attempts + 1}/${maxAttempts})`);
          await new Promise((resolve) => setTimeout(resolve, 1000));
          attempts++;
          continue;
        }
        // For any other error, log and rethrow
        console.error("Error checking passkey status:", error);
        throw error;
      }

      // If we get here, we got a response but no result yet
      console.log(`No verification result yet, waiting... (attempt ${attempts + 1}/${maxAttempts})`);
      await new Promise((resolve) => setTimeout(resolve, 1000));
      attempts++;
    }

    throw new Error("Passkey verification timeout");
  }
}
