import { useState } from 'react';
import type { StoredIdentity } from '../lib/db';

interface AccountSwitcherProps {
  identities: StoredIdentity[];
  activeIdentity: StoredIdentity;
  onSwitch: (pubkey: string) => void;
  onAddAccount: () => void;
}

function truncateKey(key: string): string {
  if (key.length <= 16) return key;
  return key.slice(0, 6) + '...' + key.slice(-4);
}

export function AccountSwitcher({ identities, activeIdentity, onSwitch, onAddAccount }: AccountSwitcherProps) {
  const [open, setOpen] = useState(false);

  return (
    <div style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '6px 12px',
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)',
          cursor: 'pointer',
          minHeight: 36,
          WebkitTapHighlightColor: 'transparent',
        }}
        aria-expanded={open}
        aria-label="Switch account"
      >
        <span
          style={{
            width: 24,
            height: 24,
            borderRadius: '50%',
            background: 'var(--accent)',
            color: 'var(--accent-text)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 12,
            fontWeight: 700,
            flexShrink: 0,
          }}
        >
          {activeIdentity.displayName.charAt(0).toUpperCase()}
        </span>
        <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
          {activeIdentity.displayName}
        </span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}>
          &#9660;
        </span>
      </button>

      {open && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            right: 0,
            minWidth: 220,
            marginTop: 4,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            boxShadow: 'var(--shadow-lg)',
            zIndex: 200,
            overflow: 'hidden',
          }}
        >
          {identities.map((id) => {
            const isActive = id.publicKey === activeIdentity.publicKey;
            return (
              <button
                key={id.publicKey}
                onClick={() => {
                  onSwitch(id.publicKey);
                  setOpen(false);
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  width: '100%',
                  padding: '10px 14px',
                  border: 'none',
                  background: isActive ? 'var(--bg-input)' : 'transparent',
                  cursor: 'pointer',
                  minHeight: 44,
                  WebkitTapHighlightColor: 'transparent',
                }}
              >
                <span
                  style={{
                    width: 28,
                    height: 28,
                    borderRadius: '50%',
                    background: isActive ? 'var(--accent)' : 'var(--border)',
                    color: isActive ? 'var(--accent-text)' : 'var(--text-secondary)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: 13,
                    fontWeight: 700,
                    flexShrink: 0,
                  }}
                >
                  {id.displayName.charAt(0).toUpperCase()}
                </span>
                <div style={{ textAlign: 'left', flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
                    {id.displayName}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                    {truncateKey(id.publicKey)}
                    {id.importMethod === 'nsec' ? ' (nsec)' : ''}
                  </div>
                </div>
                {isActive && (
                  <span style={{ fontSize: 14, color: 'var(--accent)' }}>&#10003;</span>
                )}
              </button>
            );
          })}

          <button
            onClick={() => {
              onAddAccount();
              setOpen(false);
            }}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              width: '100%',
              padding: '10px 14px',
              border: 'none',
              borderTop: '1px solid var(--border)',
              background: 'transparent',
              cursor: 'pointer',
              minHeight: 44,
              WebkitTapHighlightColor: 'transparent',
            }}
          >
            <span
              style={{
                width: 28,
                height: 28,
                borderRadius: '50%',
                background: 'var(--bg-input)',
                border: '1px dashed var(--border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 16,
                color: 'var(--text-muted)',
                flexShrink: 0,
              }}
            >
              +
            </span>
            <span style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-secondary)' }}>
              Add Account
            </span>
          </button>
        </div>
      )}
    </div>
  );
}
