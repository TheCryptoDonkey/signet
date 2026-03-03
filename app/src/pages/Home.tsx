import { useState, useCallback, useMemo } from 'react';
import { computeTrustScore, type NostrEvent } from 'signet-protocol';
import type { StoredIdentity } from '../lib/db';
import { createQRPayload, serializeQRPayload } from '../lib/signet';
import { QRCode } from '../components/QRCode';
import { TierBadge } from '../components/TierBadge';
import { TrustScore } from '../components/TrustScore';

interface HomeProps {
  identity: StoredIdentity;
  credentials?: NostrEvent[];
  vouches?: NostrEvent[];
  bridges?: NostrEvent[];
}

const roleLabels: Record<StoredIdentity['role'], string> = {
  adult: 'Adult',
  child: 'Child',
  verifier: 'Verifier',
};

function truncateKey(key: string): string {
  if (key.length <= 20) return key;
  return key.slice(0, 8) + '...' + key.slice(-8);
}

export function Home({ identity, credentials = [], vouches = [], bridges = [] }: HomeProps) {
  const [copied, setCopied] = useState(false);

  const trustBreakdown = useMemo(
    () => computeTrustScore(identity.publicKey, credentials, vouches, identity.createdAt, bridges),
    [identity.publicKey, identity.createdAt, credentials, vouches, bridges],
  );

  const hasBridge = bridges.length > 0;

  const qrData = useMemo(() => {
    const payload = createQRPayload(identity.publicKey, {
      name: identity.displayName,
    });
    return serializeQRPayload(payload);
  }, [identity.publicKey, identity.displayName]);

  const handleCopyKey = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(identity.publicKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers or non-secure contexts
      const textArea = document.createElement('textarea');
      textArea.value = identity.publicKey;
      textArea.style.position = 'fixed';
      textArea.style.left = '-9999px';
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [identity.publicKey]);

  const handleShare = useCallback(() => {
    alert('Sharing is not yet implemented. Use the QR code for in-person connections.');
  }, []);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        maxWidth: 480,
        margin: '0 auto',
        width: '100%',
      }}
    >
      {/* Display name */}
      <h1
        style={{
          fontSize: 28,
          fontWeight: 700,
          color: 'var(--text-primary)',
          textAlign: 'center',
          marginBottom: 8,
          wordBreak: 'break-word',
        }}
      >
        {identity.displayName}
      </h1>

      {/* Role badge */}
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 20,
        }}
      >
        <span
          style={{
            display: 'inline-block',
            padding: '4px 12px',
            borderRadius: 999,
            fontSize: 12,
            fontWeight: 600,
            letterSpacing: 0.3,
            textTransform: 'uppercase',
            background: 'var(--bg-input)',
            color: 'var(--text-secondary)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          {roleLabels[identity.role]}
        </span>
        <TierBadge tier={trustBreakdown.tier} size="md" />
        {identity.importMethod === 'nsec' && (
          <span
            style={{
              display: 'inline-block',
              padding: '4px 8px',
              borderRadius: 999,
              fontSize: 10,
              fontWeight: 600,
              background: 'var(--warning)',
              color: '#000',
            }}
          >
            nsec
          </span>
        )}
      </div>

      {/* QR Code card */}
      <div
        className="card"
        style={{
          width: '100%',
          marginBottom: 16,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          padding: 24,
        }}
      >
        <QRCode data={qrData} size={200} />

        {/* Public key */}
        <button
          onClick={handleCopyKey}
          style={{
            marginTop: 16,
            padding: '8px 16px',
            background: 'var(--bg-input)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            minHeight: 44,
            width: '100%',
            justifyContent: 'center',
            transition: 'background 0.15s',
          }}
          title="Tap to copy public key"
          aria-label="Copy public key to clipboard"
        >
          <span
            style={{
              fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
              fontSize: 13,
              color: 'var(--text-secondary)',
              letterSpacing: 0.5,
            }}
          >
            {truncateKey(identity.publicKey)}
          </span>
          <span
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: copied ? 'var(--success)' : 'var(--accent)',
              whiteSpace: 'nowrap',
              transition: 'color 0.15s',
            }}
          >
            {copied ? 'Copied!' : 'Copy'}
          </span>
        </button>
      </div>

      {/* Bridge indicator */}
      {hasBridge && (
        <div
          className="card"
          style={{
            width: '100%',
            marginBottom: 16,
            padding: '12px 16px',
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            background: 'var(--bg-card)',
          }}
        >
          <span style={{ fontSize: 18 }}>&#128279;</span>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
              Linked to verified identity
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Ring signature bridge active (+{trustBreakdown.signals.find(s => s.type === 'identity-bridge')?.weight.toFixed(0) ?? '0'} trust)
            </div>
          </div>
        </div>
      )}

      {/* Trust score card */}
      <div
        className="card"
        style={{
          width: '100%',
          marginBottom: 16,
        }}
      >
        <TrustScore score={trustBreakdown.score} showBreakdown={credentials.length > 0 || vouches.length > 0 || bridges.length > 0} />
      </div>

      {/* Share button */}
      <button
        className="btn btn-primary"
        onClick={handleShare}
        style={{
          width: '100%',
          minHeight: 48,
          fontSize: 16,
          marginTop: 4,
        }}
      >
        Share my QR
      </button>
    </div>
  );
}
