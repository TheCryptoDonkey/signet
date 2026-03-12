/** Zero out a Uint8Array buffer (best-effort secure wipe). */
export function zeroBytes(buf: Uint8Array): void {
  buf.fill(0);
}

/**
 * Constant-time comparison of two Uint8Arrays.
 * Always compares all bytes; does not short-circuit.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
