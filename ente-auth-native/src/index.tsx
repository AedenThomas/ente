import { ActionPanel, Action, Form, showToast, Toast, useNavigation, List } from "@raycast/api";
import React, { useState, useEffect } from "react";
import { SRPAuth } from "./auth/srp";
import { PasskeyAuth } from "./auth/passkey";
import { SessionManager } from "./auth/session";
import { TokenManager } from "./auth/token";
import { Clipboard } from "@raycast/api";
import { generateOTPs, Code } from "./services/otp";
import { decryptAuthenticatorData, AuthenticatorKey } from "./services/crypto";
import fetch from "node-fetch";

interface MainViewProps {
  onLogout?: () => void;
}

function MainView({ onLogout }: MainViewProps): JSX.Element {
  const { pop } = useNavigation();
  const [codes, setCodes] = useState<Code[]>([]);
  const [otpMap, setOtpMap] = useState<Record<string, [string, string]>>({});
  const [isLoading, setIsLoading] = useState(true);
  const sessionManager = new SessionManager();

  useEffect(() => {
    fetchCodes();
    const interval = setInterval(fetchCodes, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
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
      console.log("Fetching authentication codes...");
      const token = await sessionManager.getToken();
      console.log("Got token:", token ? "Token exists" : "No token found");

      if (!token) {
        throw new Error("No authentication token found");
      }

      // First, get the authenticator key
      console.log("Fetching authenticator key...");
      const keyResponse = await fetch("https://api.ente.io/authenticator/key", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      console.log("Key response status:", keyResponse.status);
      const keyResponseText = await keyResponse.text();
      console.log("Key response body:", keyResponseText);

      if (!keyResponse.ok) {
        if (keyResponse.status === 404) {
          console.log("No authenticator key found - user might not have any codes yet");
          setCodes([]);
          return;
        }
        throw new Error(`Failed to fetch authenticator key: ${keyResponse.status} ${keyResponseText}`);
      }

      const keyData = JSON.parse(keyResponseText) as AuthenticatorKey;
      const authenticatorKey = await decryptAuthenticatorData(keyData.encryptedKey);

      // Then, get the authenticator entities
      console.log("Fetching authenticator entities...");
      const codesResponse = await fetch("https://api.ente.io/authenticator/diff", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          sinceTime: 0,
          limit: 500,
        }),
      });

      console.log("Codes response status:", codesResponse.status);
      const codesResponseText = await codesResponse.text();
      console.log("Codes response body:", codesResponseText);

      if (!codesResponse.ok) {
        throw new Error(`Failed to fetch codes: ${codesResponse.status} ${codesResponseText}`);
      }

      let data;
      try {
        data = JSON.parse(codesResponseText);
        // Filter out deleted codes and transform to our Code type
        const activeCodes = await Promise.all(
          data
            .filter((entity: { isDeleted: boolean }) => !entity.isDeleted)
            .map(async (entity: { id: string; data: string }) => {
              try {
                const decryptedData = await decryptAuthenticatorData(entity.data, authenticatorKey);
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
                  algorithm: (url.searchParams.get("algorithm") || "sha1").toLowerCase() as
                    | "sha1"
                    | "sha256"
                    | "sha512",
                  counter: url.searchParams.get("counter")
                    ? parseInt(url.searchParams.get("counter") || "0")
                    : undefined,
                  secret: url.searchParams.get("secret") || "",
                } as Code;
              } catch (error) {
                console.error("Failed to parse code URI:", error);
                return null;
              }
            }),
        );

        const validCodes = activeCodes.filter((code): code is Code => code !== null);
        console.log("Parsed codes:", validCodes);
        setCodes(validCodes);
      } catch (parseError) {
        console.error("Failed to parse response:", parseError);
        throw new Error("Invalid response format from server");
      }
    } catch (error) {
      console.error("Error in fetchCodes:", error);
      await showToast({
        style: Toast.Style.Failure,
        title: "Error",
        message: error instanceof Error ? error.message : "Failed to fetch authentication codes",
      });
    } finally {
      setIsLoading(false);
    }
  }

  async function handleLogout() {
    try {
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

  return (
    <List>
      {codes.map((code) => {
        const [currentOTP, nextOTP] = otpMap[code.id] || ["", ""];
        return (
          <List.Item
            key={code.id}
            title={code.issuer}
            subtitle={code.account}
            accessories={[{ text: currentOTP }, { text: `Next: ${nextOTP}` }]}
            actions={
              <ActionPanel>
                <Action title="Copy Current Code" onAction={() => copyToClipboard(currentOTP)} />
                <Action title="Copy Next Code" onAction={() => copyToClipboard(nextOTP)} />
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

  const srpAuth = new SRPAuth();
  const passkeyAuth = new PasskeyAuth();
  const sessionManager = new SessionManager();
  const tokenManager = new TokenManager();

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

          await showToast({
            style: Toast.Style.Success,
            title: "Success",
            message: "Successfully logged in with passkey",
          });

          push(<MainView />);
          return;
        }

        session = otpResponse;
      } else {
        try {
          // Try normal SRP authentication
          session = await srpAuth.login(email, password);
        } catch (error) {
          if (error instanceof Error && error.message === "EMAIL_MFA_REQUIRED") {
            setShowOTPField(true);
            await showToast({
              style: Toast.Style.Success,
              title: "OTP Sent",
              message: "Please check your email for the verification code",
            });
            setIsLoading(false);
            return;
          }
          throw error;
        }
      }

      await tokenManager.saveToken(session);
      await tokenManager.saveUserId(session.id.toString());

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
        message: error instanceof Error ? error.message : "An error occurred during authentication",
      });
    } finally {
      if (!showOTPField) {
        setIsLoading(false);
      }
    }
  }

  return (
    <Form
      actions={
        <ActionPanel>
          <Action.SubmitForm title={showOTPField ? "Verify OTP" : "Login"} onSubmit={handleSubmit} />
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
