import { Action, ActionPanel, Form, showToast, Toast, useNavigation } from "@raycast/api";
import { useState } from "react";
import { getApiClient } from "./services/api";
import { getStorageService } from "./services/storage";
import { 
  deriveKeyEncryptionKey, 
  decryptMasterKey, 
  decryptSecretKey, 
  decryptSessionToken 
} from "./services/crypto";
import { AuthorizationResponse, UserCredentials } from "./types";
import Index from "./index";

export default function Login() {
  const { push } = useNavigation();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [otpRequested, setOtpRequested] = useState(false);

  const handleSubmit = async (values: { 
    email: string; 
    password?: string;
    otp?: string;
  }) => {
    if (!values.email) {
      setError("Email is required");
      return;
    }
    
    setIsLoading(true);
    setError(undefined);
    
    try {
      const apiClient = await getApiClient();
      
      if (!otpRequested) {
        const toast = await showToast({ style: Toast.Style.Animated, title: "Requesting code..." });
        await apiClient.requestEmailOTP(values.email);
        setOtpRequested(true);
        toast.style = Toast.Style.Success;
        toast.title = "Verification code sent";
      } else {
        if (!values.otp || !values.password) {
            setError("Password and verification code are required");
            setIsLoading(false);
            return;
        }

        const toast = await showToast({ style: Toast.Style.Animated, title: "Verifying and decrypting..." });
        const response: AuthorizationResponse = await apiClient.verifyEmailOTP(values.email, values.otp);
        console.log("DEBUG: Received authorization response from API.");

        // [Step 1] Derive the KEK from the password
        const keyEncryptionKey = await deriveKeyEncryptionKey(
            values.password,
            response.keyAttributes.kekSalt,
            response.keyAttributes.memLimit,
            response.keyAttributes.opsLimit
        );
        
        // [Step 2] Decrypt the Master Key (MK) using the KEK
        const masterKey = decryptMasterKey(
            response.keyAttributes.encryptedKey,
            response.keyAttributes.keyDecryptionNonce,
            keyEncryptionKey
        );
        
        // [Step 3] Decrypt the Secret Key (SK) using the MK
        const secretKey = decryptSecretKey(
            response.keyAttributes.encryptedSecretKey,
            response.keyAttributes.secretKeyDecryptionNonce,
            masterKey
        );

        // [Step 4] Decrypt the Session Token using the SECRET KEY (SK) and the SECRET KEY'S NONCE
        const token = decryptSessionToken(
            response.encryptedToken,
            response.keyAttributes.secretKeyDecryptionNonce,
            secretKey
        );

        if (!token) {
            throw new Error("Decrypted token is empty. Final decryption failed.");
        }

        const storage = getStorageService();
        const credentials: UserCredentials = {
          email: values.email,
          token: token,
          masterKey: masterKey,
          keyAttributes: response.keyAttributes
        };

        storage.setMasterKey(masterKey);
        await storage.storeCredentials(credentials);
        console.log("DEBUG: Login successful. Credentials stored securely.");

        toast.style = Toast.Style.Success;
        toast.title = "Login successful!";
        
        push(<Index />);
      }
    } catch (error) {
      console.error("Login error:", error);
      const message = error instanceof Error ? error.message : "An unknown error occurred";
      setError(message);
      await showToast({
        style: Toast.Style.Failure,
        title: "Login failed",
        message: message,
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <Form
      actions={
        <ActionPanel>
          <Action.SubmitForm title={otpRequested ? "Login" : "Send Code"} onSubmit={handleSubmit} />
        </ActionPanel>
      }
      isLoading={isLoading}
    >
      <Form.TextField
        id="email"
        title="Email"
        placeholder="Enter your Ente email"
        error={error}
        onChange={() => setError(undefined)}
      />
      {otpRequested && (
        <>
            <Form.PasswordField
                id="password"
                title="Password"
                placeholder="Enter your Ente password"
            />
            <Form.TextField
                id="otp"
                title="Verification Code"
                placeholder="Enter code from email"
            />
        </>
      )}
      <Form.Description text={otpRequested ? "Enter your password and the verification code sent to your email." : "We'll send a verification code to your email to log in."} />
    </Form>
  );
}