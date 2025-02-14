export function debugLog(...args: any[]): void {
  if (process.env.RAYCAST_DEBUG === "true") {
    console.debug(new Date().toISOString(), ...args);
  }
}

