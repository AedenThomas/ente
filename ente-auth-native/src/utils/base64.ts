import { Buffer } from "buffer";

/**
 * Converts a base64 string to a Uint8Array, handling URL-safe base64 and padding correctly
 */
export function base64ToBytes(base64: string): Uint8Array {
  console.log("[base64ToBytes] Input base64 string length:", base64.length);
  console.log("[base64ToBytes] First/last 10 chars:", base64.slice(0, 10) + "..." + base64.slice(-10));

  // Replace URL-safe characters with standard base64 characters
  const standardBase64 = base64.replace(/-/g, "+").replace(/_/g, "/");
  console.log(
    "[base64ToBytes] After URL-safe conversion:",
    standardBase64.slice(0, 10) + "..." + standardBase64.slice(-10)
  );

  // Add padding if necessary
  const padded = standardBase64.padEnd(Math.ceil(standardBase64.length / 4) * 4, "=");
  console.log("[base64ToBytes] After padding:", padded.slice(0, 10) + "..." + padded.slice(-10));

  try {
    const bytes = new Uint8Array(Buffer.from(padded, "base64"));
    console.log("[base64ToBytes] Decoded bytes length:", bytes.length);
    console.log("[base64ToBytes] First 5 bytes:", Array.from(bytes.slice(0, 5)));
    return bytes;
  } catch (error) {
    console.error("[base64ToBytes] Failed to decode base64:", {
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
  console.log("[bytesToBase64] Input bytes length:", bytes.length);
  console.log("[bytesToBase64] First 5 bytes:", Array.from(bytes.slice(0, 5)));

  try {
    const base64 = Buffer.from(bytes).toString("base64");
    console.log("[bytesToBase64] Output base64 length:", base64.length);
    console.log("[bytesToBase64] First/last 10 chars:", base64.slice(0, 10) + "..." + base64.slice(-10));
    return base64;
  } catch (error) {
    console.error("[bytesToBase64] Failed to encode bytes:", error);
    throw error;
  }
}
