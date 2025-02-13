import _sodium from "libsodium-wrappers";

class Sodium {
  private sodium: typeof _sodium;
  private initialized = false;

  async init() {
    if (!this.initialized) {
      await _sodium.ready;
      this.sodium = _sodium;
      this.initialized = true;
    }
  }

  async crypto_secretbox_open_easy(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    await this.init();
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
    password: Uint8Array,
    salt: Uint8Array,
    opsLimit: number,
    memLimit: number
  ): Promise<Uint8Array> {
    await this.init();
    return this.sodium.crypto_pwhash(
      keyLength,
      password,
      salt,
      opsLimit,
      memLimit,
      this.sodium.crypto_pwhash_ALG_ARGON2ID13
    );
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
    console.log(`[sodium] Deriving subkey with context '${context}' (padded to '${contextStr}')`);
    console.log(`[sodium] subkeyLen=${subkeyLen}, subkeyId=${subkeyId}, keyLength=${key.length}`);
    return this.sodium.crypto_kdf_derive_from_key(subkeyLen, subkeyId, contextStr, key);
  }
}

export const sodium = new Sodium();
