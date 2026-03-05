/** Truncate a hex key for display. */
export function truncatePubkey(key: string, startLen = 8, endLen = 8): string {
  if (key.length <= startLen + endLen + 3) return key;
  return `${key.slice(0, startLen)}...${key.slice(-endLen)}`;
}

/** Format a unix timestamp as relative time. */
export function timeAgo(timestampSeconds: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestampSeconds;
  if (diff < 60) return 'just now';
  if (diff < 3600) { const m = Math.floor(diff / 60); return `${m}m ago`; }
  if (diff < 86400) { const h = Math.floor(diff / 3600); return `${h}h ago`; }
  const d = Math.floor(diff / 86400);
  if (d < 30) return `${d}d ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  const y = Math.floor(d / 365);
  return `${y}y ago`;
}
