import _sodium from "libsodium-wrappers";

class Sodium {
  private sodium!: typeof _sodium;
  private initialized = false;

  async init() {
    if (!this.initialized) {
      await _sodium.ready;
      this.sodium = _sodium;
      this.initialized = true;
      console.debug("[sodium.init] Initialized with version:", this.sodium.SODIUM_VERSION_STRING);
      console.debug(
        "[sodium.init] Available crypto functions:",
        Object.keys(this.sodium).filter((key) => key.startsWith("crypto_"))
      );
    } else {
      console.debug("[sodium.init] Already initialized");
    }
  }

  async crypto_secretbox_open_easy(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    await this.init();
    console.debug("[sodium.crypto_secretbox_open_easy] Called with ciphertext length:", ciphertext.length, "nonce length:", nonce.length);
    return this.sodium.crypto_secretbox_open_easy(ciphertext, nonce, key);
  }

  async crypto_box_seal_open(
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    secretKey: Uint8Array
  ): Promise<Uint8Array> {
    await this.init();
    return this.sodium.crypto_box_seal_open(ciphertext, publicKey, secretKey);
  }

  async crypto_pwhash(
    keyLength: number,
    password: Uint8Array | string,
    salt: Uint8Array,
    opsLimit: number,
    memLimit: number
  ): Promise<Uint8Array> {
    await this.init();
    try {
      console.log("[sodium.crypto_pwhash] Starting with params:", {
        keyLength,
        passwordType: typeof password,
        passwordLength: typeof password === "string" ? password.length : password.length,
        passwordFirstBytes:
          typeof password === "string"
            ? Array.from(Buffer.from(password).slice(0, 5))
            : Array.from(password.slice(0, 5)),
        saltLength: salt.length,
        saltFirstBytes: Array.from(salt.slice(0, 5)),
        opsLimit,
        memLimit,
        saltBase64: Buffer.from(salt).toString("base64"),
      });

      // Convert password to Uint8Array if it's a string
      const passwordBytes = typeof password === "string" ? this.sodium.from_string(password) : password;
      console.log("[sodium.crypto_pwhash] Password prepared:", {
        passwordBytesLength: passwordBytes.length,
        passwordBytesFirstBytes: Array.from(passwordBytes.slice(0, 5)),
        passwordBytesType: Object.prototype.toString.call(passwordBytes),
        isBuffer: passwordBytes instanceof Buffer,
        passwordBytesBase64: Buffer.from(passwordBytes).toString("base64"),
      });

      // Use the correct function name from libsodium-wrappers
      const pwHash = this.sodium.crypto_generichash(keyLength, passwordBytes, salt);

      console.log("[sodium.crypto_pwhash] Key derived:", {
        pwHashLength: pwHash.length,
        pwHashFirstBytes: Array.from(pwHash.slice(0, 5)),
        pwHashType: Object.prototype.toString.call(pwHash),
        isBuffer: pwHash instanceof Buffer,
        pwHashBase64: Buffer.from(pwHash).toString("base64"),
      });

      return pwHash;
    } catch (error) {
      console.error("[sodium.crypto_pwhash] Failed:", {
        error: error instanceof Error ? error.message : "Unknown error",
        stack: error instanceof Error ? error.stack : undefined,
        sodiumVersion: this.sodium.SODIUM_VERSION_STRING,
        availableFunctions: Object.keys(this.sodium).filter((key) => key.startsWith("crypto_")),
        keyLength,
        passwordType: typeof password,
        saltLength: salt.length,
      });
      throw error;
    }
  }

  async crypto_kdf_derive_from_key(
    subkeyLen: number,
    subkeyId: number,
    context: string,
    key: Uint8Array
  ): Promise<Uint8Array> {
    await this.init();
    // Pad or truncate the context to exactly 8 bytes using the same method as libsodium
    const contextStr = context.slice(0, 8).padEnd(8, "\0");
    console.log(`[sodium.crypto_kdf_derive_from_key] Starting key derivation:`, {
      subkeyLen,
      subkeyId,
      context,
      paddedContext: contextStr,
      keyLength: key.length,
      keyFirstBytes: Array.from(key.slice(0, 5)),
      keyType: Object.prototype.toString.call(key),
      isBuffer: key instanceof Buffer,
      keyBase64: Buffer.from(key).toString("base64"),
    });

    const result = await this.sodium.crypto_kdf_derive_from_key(subkeyLen, subkeyId, contextStr, key);

    console.log(`[sodium.crypto_kdf_derive_from_key] Key derived:`, {
      resultLength: result.length,
      resultFirstBytes: Array.from(result.slice(0, 5)),
      resultType: Object.prototype.toString.call(result),
      isBuffer: result instanceof Buffer,
      resultBase64: Buffer.from(result).toString("base64"),
    });

    return result;
  }

  async crypto_secretbox_easy(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    await this.init();
    return this.sodium.crypto_secretbox_easy(message, nonce, key);
  }

  async crypto_box_seal(message: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
    await this.init();
    return this.sodium.crypto_box_seal(message, publicKey);
  }

  async randombytes_buf(length: number): Promise<Uint8Array> {
    await this.init();
    return this.sodium.randombytes_buf(length);
  }

  async crypto_secretbox_NONCEBYTES(): Promise<number> {
    await this.init();
    return this.sodium.crypto_secretbox_NONCEBYTES;
  }

  async crypto_pwhash_SALTBYTES(): Promise<number> {
    await this.init();
    return this.sodium.crypto_pwhash_SALTBYTES;
  }

  async crypto_box_PUBLICKEYBYTES(): Promise<number> {
    await this.init();
    return this.sodium.crypto_box_PUBLICKEYBYTES;
  }

  async crypto_box_SECRETKEYBYTES(): Promise<number> {
    await this.init();
    return this.sodium.crypto_box_SECRETKEYBYTES;
  }

  async crypto_box_SEALBYTES(): Promise<number> {
    await this.init();
    return this.sodium.crypto_box_SEALBYTES;
  }

  async crypto_box_keypair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    await this.init();
    const keyPair = this.sodium.crypto_box_keypair();
    return {
      publicKey: keyPair.publicKey,
      secretKey: keyPair.privateKey,
    };
  }

  async from_string(str: string): Promise<Uint8Array> {
    await this.init();
    return this.sodium.from_string(str);
  }

  async to_string(bytes: Uint8Array): Promise<string> {
    await this.init();
    return this.sodium.to_string(bytes);
  }

  async crypto_pwhash_ALG_ARGON2ID13(): Promise<number> {
    await this.init();
    return this.sodium.crypto_pwhash_ALG_ARGON2ID13;
  }
}

export const sodium = new Sodium();
