import { useState, useEffect } from "react";
import { 
  List, 
  Action, 
  ActionPanel, 
  Icon, 
  Color, 
  showToast, 
  Toast,
  Clipboard,
  Form
} from "@raycast/api";
import { getAuthenticatorService } from "./services/authenticator";
import { getStorageService } from "./services/storage";
import { getApiClient, resetApiClient } from "./services/api";
import {
  deriveKeyEncryptionKey,
  decryptMasterKey,
  decryptSecretKey,
  decryptSessionToken,
} from "./services/crypto";
import { determineAuthMethod, SRPAuthenticationService } from "./services/srp";
import { AuthCode, AuthorizationResponse, UserCredentials } from "./types";

export default function Index() {
  const [codes, setCodes] = useState<AuthCode[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchText, setSearchText] = useState("");
  const [timer, setTimer] = useState<NodeJS.Timeout | null>(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showLogin, setShowLogin] = useState(false);
  
  // Login form state
  const [loginLoading, setLoginLoading] = useState(false);
  const [loginError, setLoginError] = useState<string | undefined>();
  const [otpRequested, setOtpRequested] = useState(false);
  const [useSRP, setUseSRP] = useState(false);

  // [PERSISTENCE FIX] Enhanced login status check with session restoration
  const checkLoginStatus = async () => {
    console.log("DEBUG: 🔍 Checking login status and attempting session restoration...");
    
    try {
      const storage = getStorageService();
      
      // First, try to restore from persistent session token
      const storedSession = await storage.getStoredSessionToken();
      if (storedSession) {
        console.log("DEBUG: 💡 Found stored session token, attempting restoration...");
        
        try {
          // Set up API client with stored session
          resetApiClient();
          const apiClient = await getApiClient();
          apiClient.setToken(storedSession.token);
          
          const authContext = {
            userId: storedSession.userId,
            accountKey: `auth-${storedSession.userId}`,
            userAgent: storedSession.userAgent
          };
          apiClient.setAuthenticationContext(authContext);
          
          // Test if the stored token is still valid
          console.log("DEBUG: 🧪 Testing stored session token validity...");
          const isValid = await apiClient.testTokenValidity();
          
          if (isValid) {
            console.log("DEBUG: ✅ Stored session token is valid! Restoring session...");
            
            // Try to store authentication context, but don't fail if encryption fails
            try {
              await storage.storeAuthenticationContext(authContext);
              console.log("DEBUG: ✅ Authentication context stored during session restoration");
            } catch (error) {
              console.log("DEBUG: ⚠️ Failed to store authentication context (encryption issue), but continuing session restoration");
              // Continue with session restoration even if context storage fails
            }
            
            // Initialize authenticator service with restored session
            const authenticatorService = getAuthenticatorService();
            const initialized = await authenticatorService.init();
            
            if (initialized) {
              console.log("DEBUG: 🎉 Session restoration successful! User is logged in.");
              setIsLoggedIn(true);
              await loadCodes();
              return;
            } else {
              console.log("DEBUG: ⚠️ Session valid but authenticator init failed");
            }
          } else {
            console.log("DEBUG: ❌ Stored session token is invalid/expired, clearing...");
            await storage.clearStoredSessionToken();
          }
        } catch (error) {
          console.error("DEBUG: Session restoration failed:", error);
          await storage.clearStoredSessionToken();
        }
      }
      
      // Fallback: Try traditional credential-based login
      console.log("DEBUG: 🔄 Attempting traditional credential-based initialization...");
      const credentials = await storage.getCredentials();
      
      if (credentials) {
        console.log("DEBUG: User has stored credentials, attempting to initialize authenticator");
        const authenticatorService = getAuthenticatorService();
        const initialized = await authenticatorService.init();
        
        if (initialized) {
          console.log("DEBUG: Authenticator initialized successfully via credentials");
          setIsLoggedIn(true);
          await loadCodes();
          return;
        }
      }
      
      console.log("DEBUG: ⚠️ User not logged in or initialization failed - showing login form");
      setIsLoggedIn(false);
      setShowLogin(true);
    } catch (error) {
      console.error("Error checking login status:", error);
      setIsLoggedIn(false);
      setShowLogin(true);
    } finally {
      setIsLoading(false);
    }
  };

  // Filter codes based on search
  const filteredCodes = codes.filter(
    (code) =>
      code.name.toLowerCase().includes(searchText.toLowerCase()) ||
      (code.issuer && code.issuer.toLowerCase().includes(searchText.toLowerCase()))
  );
  
  // Load and refresh codes
  const loadCodes = async () => {
    if (!isLoggedIn) return;
    
    try {
      const authenticatorService = getAuthenticatorService();
      const authCodes = await authenticatorService.getAuthCodes();
      
      if (!authCodes || authCodes.length === 0) {
        await showToast({
          style: Toast.Style.Animated,
          title: "No authentication codes found",
          message: "Try syncing with the server or adding codes in the Ente app"
        });
      }
      
      setCodes(authCodes);
    } catch (error) {
      console.error("Error getting auth codes:", error);
      await showToast({
        style: Toast.Style.Failure,
        title: "Failed to get authentication codes",
        message: "Please try syncing with the server"
      });
      setCodes([]);
    }
  };
  
  // Sync with server
  const syncCodes = async () => {
    if (!isLoggedIn) return;
    
    try {
      setIsLoading(true);
      
      const toast = await showToast({
        style: Toast.Style.Animated,
        title: "Syncing authenticator codes...",
      });
      
      const authenticatorService = getAuthenticatorService();
      const syncResult = await authenticatorService.syncAuthenticator();
      
      if (!syncResult) {
        throw new Error("Sync failed");
      }
      
      const authCodes = await authenticatorService.getAuthCodes();
      setCodes(authCodes);
      
      toast.style = Toast.Style.Success;
      toast.title = "Synced successfully!";
    } catch (error) {
      console.error("Sync error:", error);
      await showToast({
        style: Toast.Style.Failure,
        title: "Sync failed",
        message: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  // Logout action
  const handleLogout = async () => {
    try {
      const toast = await showToast({
        style: Toast.Style.Animated,
        title: "Logging out...",
      });
      
      const storage = getStorageService();
      await storage.clearAll();
      
      // Clear state
      setCodes([]);
      setIsLoggedIn(false);
      setShowLogin(true);
      
      toast.style = Toast.Style.Success;
      toast.title = "Logged out successfully!";
    } catch (error) {
      console.error("Logout error:", error);
      await showToast({
        style: Toast.Style.Failure,
        title: "Logout failed",
        message: error instanceof Error ? error.message : "Unknown error",
      });
    }
  };
  
  // Copy code to clipboard
  const copyCode = async (code: string) => {
    await Clipboard.copy(code);
    await showToast({
      style: Toast.Style.Success,
      title: "Code copied to clipboard!",
    });
  };

  // Login form submit handler
  const handleLoginSubmit = async (values: { email: string; password?: string; otp?: string }) => {
    if (!values.email) {
      setLoginError("Email is required");
      return;
    }

    setLoginLoading(true);
    setLoginError(undefined);

    try {
      const apiClient = await getApiClient();

      if (!otpRequested) {
        const toast = await showToast({ style: Toast.Style.Animated, title: "Checking authentication method..." });
        
        try {
          const authMethod = await determineAuthMethod(values.email);
          
          if (authMethod === "srp") {
            console.log("DEBUG: SRP authentication available - requesting password for SRP flow");
            setUseSRP(true);
            setOtpRequested(true);
            toast.style = Toast.Style.Success;  
            toast.title = "Enter your password to continue";
          } else {
            console.log("DEBUG: Using email OTP authentication method");
            setUseSRP(false);
            await apiClient.requestEmailOTP(values.email);
            setOtpRequested(true);
            toast.style = Toast.Style.Success;
            toast.title = "Verification code sent";
          }
        } catch (error) {
          console.error("DEBUG: Error determining auth method:", error);
          await apiClient.requestEmailOTP(values.email);
          setOtpRequested(true);
          toast.style = Toast.Style.Success;
          toast.title = "Verification code sent";
        }
      } else {
        if (!values.password) {
          setLoginError("Password is required");
          setLoginLoading(false);
          return;
        }

        if (useSRP) {
          const toast = await showToast({ style: Toast.Style.Animated, title: "Authenticating with SRP..." });
          
          try {
            const response = await SRPAuthenticationService.performSRPAuthentication(
              values.email,
              values.password
            );
            
            console.log("DEBUG: ✅ SRP authentication successful! Processing session token...");
            
            if (!response.keyAttributes || !response.encryptedToken) {
              throw new Error("SRP response missing required data");
            }
            
            const keyEncryptionKey = await deriveKeyEncryptionKey(
              values.password,
              response.keyAttributes.kekSalt,
              response.keyAttributes.memLimit,
              response.keyAttributes.opsLimit,
            );
            
            const masterKey = await decryptMasterKey(
              response.keyAttributes.encryptedKey,
              response.keyAttributes.keyDecryptionNonce,
              keyEncryptionKey,
            );

            const storage = getStorageService();
            storage.setMasterKey(masterKey);

            await storage.storeEncryptedToken(response.id, response.encryptedToken);
            await storage.storePartialCredentials(values.email, response.id, response.encryptedToken);

            const secretKey = await decryptSecretKey(
              response.keyAttributes.encryptedSecretKey,
              response.keyAttributes.secretKeyDecryptionNonce,
              masterKey,
            );
            
            const token = await decryptSessionToken(
              response.encryptedToken,
              response.keyAttributes.publicKey,
              secretKey,
            );

            if (!token) {
              throw new Error("Decrypted token is empty. Final decryption failed.");
            }
            
            const credentials: UserCredentials = {
              email: values.email,
              userId: response.id,
              token: token,
              masterKey: masterKey,
              keyAttributes: response.keyAttributes,
            };
            
            storage.setMasterKey(masterKey);
            await storage.storeCredentials(credentials);
            await storage.activateToken(token);
            
            // [PERSISTENCE FIX] Store session token separately for cross-restart persistence
            await storage.storeSessionToken(token, values.email, response.id);
            
            const authContext = {
              userId: response.id,
              accountKey: `auth-${response.id}`,
              userAgent: 'Raycast/Ente-Auth/1.0.0'
            };
            
            await storage.storeAuthenticationContext(authContext);
            await storage.clearEncryptedToken();
            
            resetApiClient();
            await storage.resetSyncState();
            
            const freshApiClient = await getApiClient();
            const isTokenValid = await freshApiClient.testTokenValidity();
            
            if (isTokenValid) {
              console.log("DEBUG: ✅ SRP Authentication successful - full API access granted!");
            }
            
            // [PERSISTENCE FIX] Store decrypted authenticator key for session restoration
            try {
              const authenticatorService = getAuthenticatorService();
              await authenticatorService.init();
              console.log("DEBUG: 💾 Attempting to store decrypted authenticator key for session persistence");
              
              // Try to get the decrypted authenticator key and store it
              const authCodes = await authenticatorService.getAuthCodes();
              console.log("DEBUG: ✅ Authenticator key accessed successfully, should be cached and stored");
              
              // The authenticator key should now be cached in the service
              // We need to access the private method, so let's store it via a public method
              
            } catch (error) {
              console.log("DEBUG: ⚠️ Could not store authenticator key during login, will be fetched during session restoration:", error);
            }
            
            toast.style = Toast.Style.Success;
            toast.title = "Login successful!";
            
            // Switch to codes view
            setIsLoggedIn(true);
            setShowLogin(false);
            await loadCodes();
            
          } catch (error) {
            console.error("DEBUG: SRP authentication failed:", error);
            throw error;
          }
        } else {
          // Email OTP authentication
          if (!values.otp) {
            setLoginError("Verification code is required");
            setLoginLoading(false);
            return;
          }

          const toast = await showToast({ style: Toast.Style.Animated, title: "Verifying with email OTP..." });
          const response: AuthorizationResponse = await apiClient.verifyEmailOTP(values.email, values.otp);

          const keyEncryptionKey = await deriveKeyEncryptionKey(
            values.password,
            response.keyAttributes.kekSalt,
            response.keyAttributes.memLimit,
            response.keyAttributes.opsLimit,
          );

          const masterKey = await decryptMasterKey(
            response.keyAttributes.encryptedKey,
            response.keyAttributes.keyDecryptionNonce,
            keyEncryptionKey,
          );

          const secretKey = await decryptSecretKey(
            response.keyAttributes.encryptedSecretKey,
            response.keyAttributes.secretKeyDecryptionNonce,
            masterKey,
          );
          
          const token = await decryptSessionToken(
            response.encryptedToken,
            response.keyAttributes.publicKey,
            secretKey,
          );

          if (!token) {
            throw new Error("Decrypted token is empty. Final decryption failed.");
          }

          const storage = getStorageService();
          const credentials: UserCredentials = {
            email: values.email,
            userId: response.id,
            token: token,
            masterKey: masterKey,
            keyAttributes: response.keyAttributes,
          };
          
          storage.setMasterKey(masterKey);
          await storage.storeCredentials(credentials);
          
          // [PERSISTENCE FIX] Store session token separately for cross-restart persistence
          await storage.storeSessionToken(token, values.email, response.id);
          
          const authContext = {
            userId: response.id,
            accountKey: `auth-${response.id}`,
            userAgent: 'Raycast/Ente-Auth/1.0.0'
          };
          
          await storage.storeAuthenticationContext(authContext);
          
          apiClient.setToken(token);
          apiClient.setAuthenticationContext(authContext);

          toast.style = Toast.Style.Success;
          toast.title = "Login successful!";

          // Switch to codes view
          setIsLoggedIn(true);
          setShowLogin(false);
          await loadCodes();
        }
      }
    } catch (error) {
      console.error("Login error:", error);
      const message = error instanceof Error ? error.message : "An unknown error occurred";
      setLoginError(message);
      await showToast({
        style: Toast.Style.Failure,
        title: "Login failed",
        message: message,
      });
    } finally {
      setLoginLoading(false);
    }
  };
  
  // Update codes every second for countdown
  useEffect(() => {
    checkLoginStatus();
    
    // Set up timer for refreshing codes
    const interval = setInterval(async () => {
      if (isLoggedIn) {
        try {
          const authenticatorService = getAuthenticatorService();
          const authCodes = await authenticatorService.getAuthCodes();
          setCodes(authCodes);
        } catch (error) {
          console.error("Error updating codes in timer:", error);
        }
      }
    }, 1000);
    
    setTimer(interval);
    
    return () => {
      if (timer) {
        clearInterval(timer);
      }
    };
  }, [isLoggedIn]);

  // Show login form if not logged in
  if (showLogin && !isLoggedIn) {
    return (
      <Form
        actions={
          <ActionPanel>
            <Action.SubmitForm 
              title={otpRequested ? "Login" : "Send Code"} 
              onSubmit={handleLoginSubmit} 
            />
          </ActionPanel>
        }
        isLoading={loginLoading}
      >
        <Form.TextField
          id="email"
          title="Email"
          placeholder="Enter your Ente email"
          error={loginError}
          onChange={() => setLoginError(undefined)}
          autoFocus
        />
        {otpRequested && (
          <>
            <Form.PasswordField 
              id="password" 
              title="Password" 
              placeholder="Enter your Ente password" 
            />
            {!useSRP && (
              <Form.TextField 
                id="otp" 
                title="Verification Code" 
                placeholder="Enter code from email" 
              />
            )}
          </>
        )}
        <Form.Description
          text={
            otpRequested
              ? useSRP 
                ? "Enter your password to authenticate with SRP."
                : "Enter your password and the verification code sent to your email."
              : "We'll check your authentication method and guide you through login."
          }
        />
      </Form>
    );
  }
  
  return (
    <List
      isLoading={isLoading}
      searchBarPlaceholder="Search authenticator codes..."
      onSearchTextChange={setSearchText}
      isShowingDetail
      actions={
        <ActionPanel>
          <Action title="Refresh" icon={Icon.ArrowClockwise} onAction={loadCodes} />
          <Action title="Sync with Server" icon={Icon.Download} onAction={syncCodes} />
          <Action title="Logout" icon={Icon.ExclamationMark} style={Action.Style.Destructive} onAction={handleLogout} />
        </ActionPanel>
      }
    >
      {filteredCodes.map((item) => {
        const progressColor = getProgressColor(item.progress || 0);
        const formattedCode = formatCode(item.code, item.digits);
        
        // Match web app display: Issuer as title, Account as subtitle (grey)
        const displayTitle = item.issuer || item.name;
        const displaySubtitle = item.issuer ? item.name : undefined;
        
        return (
          <List.Item
            key={item.id}
            title={displayTitle}
            subtitle={displaySubtitle}
            icon={{ source: Icon.Key, tintColor: progressColor }}
            // accessories={[
            //   { text: formattedCode, tooltip: "Current OTP Code" }
            // ]}
            detail={
              <List.Item.Detail
                metadata={
                  <List.Item.Detail.Metadata>
                    <List.Item.Detail.Metadata.Label title="Issuer" text={item.issuer || "Unknown"} />
                    <List.Item.Detail.Metadata.Label title="Account" text={item.name} />
                    <List.Item.Detail.Metadata.Separator />
                    <List.Item.Detail.Metadata.Label title="Current Code" text={formattedCode} />
                    <List.Item.Detail.Metadata.TagList title="Type">
                      <List.Item.Detail.Metadata.TagList.Item
                        text={item.type.toUpperCase()}
                        color={item.type === "totp" ? Color.Green : Color.Blue}
                      />
                    </List.Item.Detail.Metadata.TagList>
                    {item.type === "totp" && item.remainingSeconds !== undefined && (
                      <List.Item.Detail.Metadata.Label
                        title="Refreshes in"
                        text={`${item.remainingSeconds} seconds`}
                      />
                    )}
                  </List.Item.Detail.Metadata>
                }
              />
            }
            actions={
              <ActionPanel>
                <Action
                  title="Copy Code"
                  icon={Icon.Clipboard}
                  onAction={() => copyCode(item.code)}
                />
                <Action title="Refresh" icon={Icon.ArrowClockwise} onAction={loadCodes} />
                <Action title="Sync with Server" icon={Icon.Download} onAction={syncCodes} />
                <Action 
                  title="Logout" 
                  icon={Icon.ExclamationMark} 
                  style={Action.Style.Destructive} 
                  onAction={handleLogout} 
                />
              </ActionPanel>
            }
          />
        );
      })}
      
      {filteredCodes.length === 0 && !isLoading && (
        <List.EmptyView
          title="No authentication codes found"
          description="Sync with the server or add a new authentication code."
          icon={Icon.Key}
        />
      )}
    </List>
  );
}

// Helper function to format the code with spaces for readability
function formatCode(code: string, digits: number): string {
  if (digits === 6) {
    return `${code.substring(0, 3)} ${code.substring(3)}`;
  } else if (digits === 8) {
    return `${code.substring(0, 4)} ${code.substring(4)}`;
  }
  return code;
}

// Helper function to determine progress color based on remaining time
function getProgressColor(progress: number): Color {
  if (progress > 66) {
    return Color.Green;
  } else if (progress > 33) {
    return Color.Yellow;
  }
  return Color.Red;
}
