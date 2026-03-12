/** Zero out a Uint8Array buffer (best-effort secure wipe). */
export function zeroBytes(buf: Uint8Array): void {
  buf.fill(0);
}

/**
 * Constant-time comparison of two equal-length Uint8Arrays.
 * Always compares all bytes; does not short-circuit on content.
 *
 * NOTE: The length check IS an early return (not constant-time w.r.t. length),
 * but all callers compare fixed-size buffers (32-byte scalars), so this is safe.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
