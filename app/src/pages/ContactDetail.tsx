import { useState, useCallback, useEffect } from 'react';
import { createVouch } from 'signet-protocol';
import type { StoredConnection, StoredIdentity } from '../lib/db';
import { SignetWords } from '../components/SignetWords';
import { SignetIQ } from '../components/SignetIQ';
import { ENTITY_LABELS } from '../lib/signet';
import { publishEvent } from '../lib/relay-service';

interface ContactDetailProps {
  connection: StoredConnection;
  identity?: StoredIdentity;
  onBack: () => void;
  onRemove: (pubkey: string) => void;
  onRefreshBadge?: (pubkey: string) => Promise<import('../lib/db').CachedBadge | null>;
}

function truncatePubkey(pubkey: string): string {
  if (pubkey.length <= 16) return pubkey;
  return `${pubkey.slice(0, 8)}...${pubkey.slice(-8)}`;
}

function InfoSection({
  label,
  info,
}: {
  label: string;
  info: { name?: string; mobile?: string; email?: string; address?: string; childPubkeys?: string[] };
}) {
  const hasAnyInfo = info.name || info.mobile || info.email || info.address;

  if (!hasAnyInfo) return null;

  const rows: { key: string; label: string; value: string }[] = [];
  if (info.name) rows.push({ key: 'name', label: 'Name', value: info.name });
  if (info.mobile) rows.push({ key: 'mobile', label: 'Mobile', value: info.mobile });
  if (info.email) rows.push({ key: 'email', label: 'Email', value: info.email });
  if (info.address) rows.push({ key: 'address', label: 'Address', value: info.address });

  return (
    <div style={{ marginBottom: 20 }}>
      <h3
        style={{
          fontSize: 13,
          fontWeight: 600,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: 0.8,
          marginBottom: 10,
        }}
      >
        {label}
      </h3>
      <div
        style={{
          background: 'var(--bg-card)',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
          overflow: 'hidden',
        }}
      >
        {rows.map((row, i) => (
          <div
            key={row.key}
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '12px 16px',
              borderTop: i > 0 ? '1px solid var(--border-subtle)' : 'none',
            }}
          >
            <span style={{ fontSize: 14, color: 'var(--text-secondary)', flexShrink: 0 }}>
              {row.label}
            </span>
            <span
              style={{
                fontSize: 14,
                fontWeight: 500,
                color: 'var(--text-primary)',
                textAlign: 'right',
                marginLeft: 12,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {row.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function timeAgo(ts: number): string {
  const now = Math.floor(Date.now() / 1000);
  const diff = now - ts;
  if (diff < 60) return 'just now';
  if (diff < 3600) { const m = Math.floor(diff / 60); return `${m}m ago`; }
  if (diff < 86400) { const h = Math.floor(diff / 3600); return `${h}h ago`; }
  const d = Math.floor(diff / 86400);
  return `${d}d ago`;
}

export function ContactDetail({ connection, identity, onBack, onRemove, onRefreshBadge }: ContactDetailProps) {
  const displayName = connection.theirInfo.name || truncatePubkey(connection.pubkey);
  const [vouched, setVouched] = useState(false);
  const [vouchError, setVouchError] = useState<string | null>(null);

  // Auto-refresh badge if stale
  useEffect(() => {
    if (onRefreshBadge) {
      onRefreshBadge(connection.pubkey).catch(() => {});
    }
  }, [connection.pubkey, onRefreshBadge]);

  const handleVouch = useCallback(async () => {
    if (!identity) return;
    try {
      const vouch = await createVouch(identity.privateKey, {
        subjectPubkey: connection.pubkey,
        method: 'in-person',
        voucherTier: 1,
        voucherScore: 50,
        context: `Vouched via Signet app connection`,
      });
      await publishEvent(vouch);
      setVouched(true);
    } catch (err) {
      setVouchError(err instanceof Error ? err.message : 'Failed to publish vouch');
    }
  }, [identity, connection.pubkey]);

  const handleRemove = useCallback(() => {
    const confirmed = window.confirm(
      `Remove connection with ${displayName}? This cannot be undone.`,
    );
    if (confirmed) {
      onRemove(connection.pubkey);
    }
  }, [connection.pubkey, displayName, onRemove]);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        padding: 16,
        gap: 0,
        maxWidth: 480,
        margin: '0 auto',
        width: '100%',
      }}
    >
      {/* Header with back button */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          marginBottom: 20,
          minHeight: 44,
        }}
      >
        <button
          onClick={onBack}
          aria-label="Back"
          style={{
            background: 'none',
            border: 'none',
            fontSize: 24,
            color: 'var(--accent)',
            cursor: 'pointer',
            padding: '8px 12px 8px 0',
            minWidth: 44,
            minHeight: 44,
            display: 'flex',
            alignItems: 'center',
            WebkitTapHighlightColor: 'transparent',
          }}
        >
          &#8592;
        </button>
        <h1
          style={{
            fontSize: 20,
            fontWeight: 700,
            color: 'var(--text-primary)',
            margin: 0,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {displayName}
        </h1>
      </div>

      {/* Signet Badge */}
      {connection.badge && (
        <div style={{ marginBottom: 20 }}>
          <h3
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: 0.8,
              marginBottom: 10,
            }}
          >
            Signet Badge
          </h3>
          <div
            style={{
              background: 'var(--bg-card)',
              borderRadius: 'var(--radius)',
              border: '1px solid var(--border)',
              padding: '14px 16px',
            }}
          >
            <div style={{ marginBottom: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 600, fontSize: 14 }}>
                {connection.badge.tierLabel}
                {connection.badge.entityType && (
                  <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 8 }}>
                    {ENTITY_LABELS[connection.badge.entityType as keyof typeof ENTITY_LABELS] ?? connection.badge.entityType}
                  </span>
                )}
              </span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Tier {connection.badge.tier}
              </span>
            </div>
            <SignetIQ
              breakdown={{
                score: connection.badge.score,
                tier: connection.badge.tier as 1 | 2 | 3 | 4,
                professionalVerifications: 0,
                inPersonVouches: 0,
                onlineVouches: connection.badge.vouchCount,
                accountAgeDays: 0,
                signals: [],
              }}
              showBreakdown={false}
            />
            <div style={{ marginTop: 8, display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)' }}>
              <span>Credentials: {connection.badge.credentialCount} · Vouches: {connection.badge.vouchCount}</span>
              <span>Updated {timeAgo(connection.badge.fetchedAt)}</span>
            </div>
          </div>
        </div>
      )}

      {/* Their info */}
      <InfoSection label="Their Information" info={connection.theirInfo} />

      {/* Signet Words — only for mutual (in-person) connections */}
      {connection.connectionType !== 'follow' && connection.sharedSecret && (
        <div style={{ marginBottom: 20 }}>
          <h3
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: 'var(--text-muted)',
              textTransform: 'uppercase',
              letterSpacing: 0.8,
              marginBottom: 10,
            }}
          >
            Signet Words
          </h3>
          <SignetWords sharedSecret={connection.sharedSecret} />
        </div>
      )}

      {/* Our shared info */}
      <InfoSection label="Information You Shared" info={connection.ourInfo} />

      {/* Pubkey */}
      <div style={{ marginBottom: 20 }}>
        <h3
          style={{
            fontSize: 13,
            fontWeight: 600,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: 0.8,
            marginBottom: 10,
          }}
        >
          Public Key
        </h3>
        <div
          style={{
            background: 'var(--bg-card)',
            borderRadius: 'var(--radius)',
            border: '1px solid var(--border)',
            padding: '12px 16px',
            fontSize: 12,
            fontFamily: 'monospace',
            color: 'var(--text-secondary)',
            wordBreak: 'break-all',
            lineHeight: 1.5,
          }}
        >
          {connection.pubkey}
        </div>
      </div>

      {/* Vouch button */}
      {identity && (
        <div style={{ marginBottom: 12 }}>
          {vouched ? (
            <div
              style={{
                padding: '12px 16px',
                background: 'var(--bg-input)',
                border: '1px solid var(--success)',
                borderRadius: 'var(--radius-sm)',
                fontSize: 14,
                fontWeight: 600,
                color: 'var(--success)',
                textAlign: 'center',
              }}
            >
              Vouch published
            </div>
          ) : (
            <button
              className="btn btn-primary"
              style={{ width: '100%', minHeight: 48 }}
              onClick={handleVouch}
            >
              Vouch for {displayName}
            </button>
          )}
          {vouchError && (
            <div style={{ fontSize: 13, color: 'var(--danger)', marginTop: 6 }}>
              {vouchError}
            </div>
          )}
        </div>
      )}

      {/* Remove connection */}
      <button
        className="btn btn-danger"
        style={{ marginTop: 8 }}
        onClick={handleRemove}
      >
        Remove Connection
      </button>
    </div>
  );
}
