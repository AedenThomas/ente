async getToken(): Promise<string | null> {
  try {
    const encryptedToken = await this.storage.getItem(TOKEN_KEY);
    if (!encryptedToken) {
      console.log("[TokenManager] No encrypted token found");
      return null;
    }

    console.log("[TokenManager] Decrypting token:", {
      encryptedTokenLength: encryptedToken.length,
      encryptedTokenPrefix: encryptedToken.substring(0, 10),
      encryptedTokenSuffix: encryptedToken.substring(encryptedToken.length - 10)
    });

    const decryptedTokenBytes = await decryptToken(encryptedToken);
    console.log("[TokenManager] Token decrypted:", {
      decryptedBytesLength: decryptedTokenBytes.length,
      expectedBytesLength: 32,
      firstBytes: Array.from(decryptedTokenBytes.slice(0, 5))
    });

    const token = bytesToBase64(decryptedTokenBytes, true);
    console.log("[TokenManager] Token converted to URL-safe base64:", {
      tokenLength: token.length,
      tokenPrefix: token.substring(0, 10),
      tokenSuffix: token.substring(token.length - 10),
      containsPlus: token.includes("+"),
      containsSlash: token.includes("/"),
      containsUnderscore: token.includes("_"),
      containsDash: token.includes("-"),
      containsEquals: token.includes("=")
    });

    return token;
  } catch (error) {
    console.error("[TokenManager] Failed to get token:", {
      error: error instanceof Error ? error.message : "Unknown error",
      stack: error instanceof Error ? error.stack : undefined
    });
    return null;
  }
}

async saveToken(encryptedToken: string): Promise<void> {
  try {
    console.log("[TokenManager] Saving encrypted token:", {
      encryptedTokenLength: encryptedToken.length,
      encryptedTokenPrefix: encryptedToken.substring(0, 10),
      encryptedTokenSuffix: encryptedToken.substring(encryptedToken.length - 10)
    });

    await this.storage.setItem(TOKEN_KEY, encryptedToken);
    console.log("[TokenManager] Token saved successfully");
  } catch (error) {
    console.error("[TokenManager] Failed to save token:", {
      error: error instanceof Error ? error.message : "Unknown error",
      stack: error instanceof Error ? error.stack : undefined
    });
    throw error;
  }
} 