import { Buffer } from "buffer";

/**
 * Converts a base64 string to a Uint8Array, handling URL-safe base64 and padding correctly
 */
export function base64ToBytes(base64: string): Uint8Array {
  // Replace URL-safe characters with standard base64 characters
  const standardBase64 = base64.replace(/-/g, "+").replace(/_/g, "/");

  // Add padding if necessary
  const padded = standardBase64.padEnd(Math.ceil(standardBase64.length / 4) * 4, "=");

  try {
    return new Uint8Array(Buffer.from(padded, "base64"));
  } catch (error) {
    console.error("Failed to decode base64:", {
      original: base64,
      standardized: standardBase64,
      padded,
      error,
    });
    throw error;
  }
}

/**
 * Converts a Uint8Array to a base64 string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}
