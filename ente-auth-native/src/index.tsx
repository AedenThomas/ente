import { ActionPanel, Action, Form, showToast, Toast, useNavigation, List } from "@raycast/api";
import React, { useState, useEffect } from "react";
import { SRPAuth } from "./auth/srp";
import { PasskeyAuth } from "./auth/passkey";
import { SessionManager } from "./services/sessionManager";
import { TokenManager } from "./auth/token";
import { Clipboard } from "@raycast/api";
import { generateOTPs, Code } from "./services/otp";
import { decryptAuthenticatorData } from "./services/crypto";
import { api } from "./services/api";

interface MainViewProps {
  onLogout?: () => void;
}

function MainView({ onLogout }: MainViewProps): JSX.Element {
  const { pop } = useNavigation();
  const [codes, setCodes] = useState<Code[]>([]);
  const [otpMap, setOtpMap] = useState<Record<string, [string, string]>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sessionManager] = useState(() => new SessionManager()); // Create single instance

  useEffect(() => {
    let mounted = true;
    const fetchAndUpdate = async () => {
      if (!mounted) return;
      console.debug("[fetchCodes] About to call fetchCodes");
      await fetchCodes();
    };

    fetchAndUpdate();
    const interval = setInterval(fetchAndUpdate, 30000); // Refresh every 30 seconds
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    // Generate OTPs for all codes
    const newOtpMap: Record<string, [string, string]> = {};
    codes.forEach((code) => {
      try {
        newOtpMap[code.id] = generateOTPs(code);
      } catch (error) {
        console.error(`Failed to generate OTP for code ${code.id}:`, error);
      }
    });
    setOtpMap(newOtpMap);

    // Set up timer to refresh OTPs every second
    const timer = setInterval(() => {
      const updatedOtpMap: Record<string, [string, string]> = {};
      codes.forEach((code) => {
        try {
          updatedOtpMap[code.id] = generateOTPs(code);
        } catch (error) {
          console.error(`Failed to generate OTP for code ${code.id}:`, error);
        }
      });
      setOtpMap(updatedOtpMap);
    }, 1000);

    return () => clearInterval(timer);
  }, [codes]);

  async function fetchCodes() {
    try {
      setError(null);
      const token = await sessionManager.getToken();
      console.debug("[fetchCodes] Retrieved token:", {
        token,
        tokenSnippet: token ? token.substring(0, 10) + "..." : null,
      });

      if (!token) {
        console.error("[fetchCodes] No valid token found, session expired");
        throw new Error("Session expired. Please log in again.");
      }

      console.debug("[fetchCodes] Making request to get authenticator key with token:", token);
      const keyData = await api.getAuthenticatorKey();

      if (keyData.error === "NOT_FOUND") {
        console.debug("[fetchCodes] No authenticator key found - user might not have any codes yet");
        setCodes([]);
        return;
      }

      console.debug("[fetchCodes] Decrypting authenticator key");
      await decryptAuthenticatorData(keyData.encryptedKey);

      // Then, get the authenticator entities
      console.debug("[fetchCodes] Fetching authenticator codes");

      // Log token again before making the next request
      const latestToken = await sessionManager.getToken();
      console.debug("[fetchCodes] Latest token before fetching codes:", {
        latestToken,
        snippet: latestToken ? latestToken.substring(0, 10) + "..." : null,
      });
      if (!latestToken) {
        throw new Error("Session expired while fetching codes");
      }

      const data = await api.getAuthenticatorCodes();
      const activeCodes = await Promise.all(
        data
          .filter((entity: { isDeleted: boolean }) => !entity.isDeleted)
          .map(async (entity: { id: string; data: string; header: string }) => {
            try {
              const decryptedData = await decryptAuthenticatorData(entity.data);
              const url = new URL(decryptedData);
              const issuer = url.searchParams.get("issuer") || url.pathname.split(":")[0].substring(1) || "";
              return {
                id: entity.id,
                type: url.protocol.startsWith("otpauth://totp")
                  ? "totp"
                  : url.protocol.startsWith("otpauth://hotp")
                  ? "hotp"
                  : url.hostname === "steam"
                  ? "steam"
                  : "totp",
                account: url.pathname.split(":")[1] || "",
                issuer,
                length: parseInt(url.searchParams.get("digits") || "6"),
                period: parseInt(url.searchParams.get("period") || "30"),
                algorithm: (url.searchParams.get("algorithm") || "sha1").toLowerCase() as "sha1" | "sha256" | "sha512",
                counter: url.searchParams.get("counter") ? parseInt(url.searchParams.get("counter") || "0") : undefined,
                secret: url.searchParams.get("secret") || "",
              } as Code;
            } catch (error) {
              console.error("Failed to parse code URI:", error);
              return null;
            }
          })
      );

      const validCodes = activeCodes.filter((code): code is Code => code !== null);
      setCodes(validCodes);
    } catch (error) {
      console.error("[fetchCodes] Error encountered:", error);
      const message = error instanceof Error ? error.message : "Failed to fetch authentication codes";
      setError(message);
      await showToast({
        style: Toast.Style.Failure,
        title: "Error",
        message,
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handleLogout() {
    try {
      await sessionManager.stopTokenRefreshSchedule(); // Stop token refresh scheduling
      await sessionManager.logout();
      await showToast({
        style: Toast.Style.Success,
        title: "Success",
        message: "Successfully logged out",
      });
      if (onLogout) {
        onLogout();
      }
      pop();
    } catch (error) {
      await showToast({
        style: Toast.Style.Failure,
        title: "Logout Failed",
        message: error instanceof Error ? error.message : "An error occurred during logout",
      });
    }
  }

  async function copyToClipboard(code: string) {
    try {
      await Clipboard.copy(code);
      await showToast({
        style: Toast.Style.Success,
        title: "Copied",
        message: "Code copied to clipboard",
      });
    } catch (error) {
      await showToast({
        style: Toast.Style.Failure,
        title: "Error",
        message: "Failed to copy code to clipboard",
      });
    }
  }

  if (isLoading) {
    return <List isLoading={true} />;
  }

  if (error) {
    return (
      <List>
        <List.EmptyView
          title="Error"
          description={error}
          actions={
            <ActionPanel>
              <Action title="Try Again" onAction={fetchCodes} />
              <Action title="Logout" onAction={handleLogout} />
            </ActionPanel>
          }
        />
      </List>
    );
  }

  if (codes.length === 0) {
    return (
      <List>
        <List.EmptyView
          title="No Authentication Codes"
          description="You haven't added any authentication codes yet. Add them through the mobile app first."
          actions={
            <ActionPanel>
              <Action title="Refresh" onAction={fetchCodes} />
              <Action title="Logout" onAction={handleLogout} />
            </ActionPanel>
          }
        />
      </List>
    );
  }

  return (
    <List>
      {codes.map((code) => {
        const [currentOTP, nextOTP] = otpMap[code.id] || ["", ""];
        return (
          <List.Item
            key={code.id}
            title={code.issuer}
            subtitle={code.account}
            accessories={[
              { text: currentOTP, tooltip: "Current code" },
              { text: `Next: ${nextOTP}`, tooltip: "Next code" },
            ]}
            actions={
              <ActionPanel>
                <Action title="Copy Current Code" onAction={() => copyToClipboard(currentOTP)} />
                <Action title="Copy Next Code" onAction={() => copyToClipboard(nextOTP)} />
                <Action title="Refresh" onAction={fetchCodes} />
                <Action title="Logout" onAction={handleLogout} />
              </ActionPanel>
            }
          />
        );
      })}
    </List>
  );
}

export default function Command(): JSX.Element {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOTP] = useState("");
  const [showOTPField, setShowOTPField] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const { push } = useNavigation();

  // Create shared instances
  const tokenManager = new TokenManager();
  const srpAuth = new SRPAuth(tokenManager);
  const passkeyAuth = new PasskeyAuth();
  const sessionManager = new SessionManager();

  async function handleSubmit() {
    if (!email || (!showOTPField && !password) || (showOTPField && !otp)) {
      await showToast({
        style: Toast.Style.Failure,
        title: "Invalid Input",
        message: showOTPField ? "Please enter the OTP" : "Please enter both email and password",
      });
      return;
    }

    setIsLoading(true);

    try {
      let session;

      if (showOTPField) {
        // Handle email OTP verification
        const otpResponse = await srpAuth.verifyEmailOTP(email, otp);

        // Check if passkey verification is required
        if (otpResponse.passkeySessionID) {
          await showToast({
            style: Toast.Style.Animated,
            title: "Passkey Verification",
            message: "Please complete passkey verification in your browser",
          });

          const result = await passkeyAuth.verifyPasskey(otpResponse.id.toString(), otpResponse.passkeySessionID);
          await tokenManager.saveToken(result);
          await tokenManager.saveUserId(otpResponse.id.toString());
          await sessionManager.startTokenRefreshSchedule(); // Start token refresh scheduling

          await showToast({
            style: Toast.Style.Success,
            title: "Success",
            message: "Successfully logged in with passkey",
          });

          push(<MainView />);
          return;
        }

        // Token is already saved by verifyEmailOTP
        await tokenManager.saveUserId(otpResponse.id.toString());
        await sessionManager.startTokenRefreshSchedule(); // Start token refresh scheduling
      } else {
        try {
          // Try normal SRP authentication
          session = await srpAuth.login(email, password);
          await tokenManager.saveToken(session);
          await tokenManager.saveUserId(session.id.toString());
          await sessionManager.startTokenRefreshSchedule(); // Start token refresh scheduling
        } catch (error) {
          if (error instanceof Error && error.message === "EMAIL_MFA_REQUIRED") {
            setShowOTPField(true);
            setIsLoading(false);
            return;
          }
          throw error;
        }
      }

      await showToast({
        style: Toast.Style.Success,
        title: "Success",
        message: "Successfully logged in",
      });

      push(<MainView />);
    } catch (error) {
      console.error("Authentication error:", error);
      await showToast({
        style: Toast.Style.Failure,
        title: "Authentication Failed",
        message: error instanceof Error ? error.message : "Please try again",
      });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <Form
      actions={
        <ActionPanel>
          <Action.SubmitForm title={showOTPField ? "Verify Otp" : "Login"} onSubmit={handleSubmit} />
        </ActionPanel>
      }
      isLoading={isLoading}
    >
      <Form.TextField id="email" title="Email" placeholder="Enter your email" value={email} onChange={setEmail} />
      {!showOTPField ? (
        <Form.PasswordField
          id="password"
          title="Password"
          placeholder="Enter your password"
          value={password}
          onChange={setPassword}
        />
      ) : (
        <Form.TextField
          id="otp"
          title="OTP"
          placeholder="Enter the verification code from your email"
          value={otp}
          onChange={setOTP}
        />
      )}
    </Form>
  );
}
