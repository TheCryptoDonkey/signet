import { useState, useMemo } from 'react';
import type { StoredConnection } from '../lib/db';
import { ENTITY_LABELS } from '../lib/signet';
import { truncatePubkey, timeAgo } from '../lib/utils';

interface ConnectionsProps {
  connections: StoredConnection[];
  onSelectContact: (pubkey: string) => void;
  onFollow: () => void;
}

export function Connections({ connections, onSelectContact, onFollow }: ConnectionsProps) {
  const [filter, setFilter] = useState('');

  const sorted = useMemo(() => {
    const filtered = connections.filter((c) => {
      if (!filter.trim()) return true;
      const term = filter.trim().toLowerCase();
      const name = c.theirInfo.name?.toLowerCase() ?? '';
      return name.includes(term) || c.pubkey.toLowerCase().includes(term);
    });
    return [...filtered].sort((a, b) => b.connectedAt - a.connectedAt);
  }, [connections, filter]);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        padding: 16,
        gap: 12,
        maxWidth: 480,
        margin: '0 auto',
        width: '100%',
      }}
    >
      <h1
        style={{
          fontSize: 24,
          fontWeight: 700,
          color: 'var(--text-primary)',
          margin: 0,
        }}
      >
        Connections
      </h1>

      {/* Search input */}
      <input
        className="input"
        type="text"
        placeholder="Search by name..."
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        style={{ marginBottom: 4 }}
      />

      {/* Follow button */}
      <button
        className="btn btn-secondary"
        onClick={onFollow}
        style={{ width: '100%', minHeight: 44 }}
      >
        + Follow a pubkey
      </button>

      {/* Empty state */}
      {sorted.length === 0 && (
        <div
          style={{
            textAlign: 'center',
            padding: '48px 16px',
            color: 'var(--text-muted)',
            fontSize: 15,
            lineHeight: 1.6,
          }}
        >
          {connections.length === 0
            ? 'No connections yet. Scan a QR code or follow a pubkey.'
            : 'No connections match your search.'}
        </div>
      )}

      {/* Connection cards */}
      {sorted.map((conn) => {
        const displayName = conn.theirInfo.name || truncatePubkey(conn.pubkey);

        return (
          <button
            key={conn.pubkey}
            onClick={() => onSelectContact(conn.pubkey)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 14,
              width: '100%',
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: '14px 16px',
              cursor: 'pointer',
              textAlign: 'left',
              boxShadow: 'var(--shadow)',
              transition: 'border-color 0.15s, box-shadow 0.15s',
              minHeight: 44,
              WebkitTapHighlightColor: 'transparent',
            }}
          >
            {/* Avatar placeholder */}
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: '50%',
                background: 'var(--accent)',
                color: 'var(--accent-text)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 16,
                fontWeight: 700,
                flexShrink: 0,
              }}
            >
              {(conn.theirInfo.name?.[0] ?? conn.pubkey[0]).toUpperCase()}
            </div>

            {/* Name & time */}
            <div style={{ flex: 1, minWidth: 0 }}>
              <div
                style={{
                  fontSize: 15,
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {displayName}
              </div>
              <div
                style={{
                  fontSize: 13,
                  color: 'var(--text-muted)',
                  marginTop: 2,
                }}
              >
                Connected {timeAgo(conn.connectedAt)}
              </div>
              {conn.badge && (
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                  {conn.badge.tierLabel} · IQ {conn.badge.score}
                  {conn.badge.entityType && ` · ${ENTITY_LABELS[conn.badge.entityType] ?? ''}`}
                </div>
              )}
              {conn.connectionType === 'mutual' && (
                <span style={{ fontSize: 10, color: 'var(--accent)', fontWeight: 600, marginTop: 2, display: 'inline-block' }}>IN-PERSON</span>
              )}
            </div>

            {/* Chevron */}
            <span
              style={{
                fontSize: 18,
                color: 'var(--text-muted)',
                flexShrink: 0,
              }}
            >
              &#8250;
            </span>
          </button>
        );
      })}
    </div>
  );
}
