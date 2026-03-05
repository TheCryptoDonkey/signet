import { useState, useCallback } from 'react';
import type { StoredIdentity } from '../lib/db';

interface GuardianControlsProps {
  identity: StoredIdentity;
  identities: StoredIdentity[];
  onBack: () => void;
}

type DmPolicy = 'block_all' | 'approve_only' | 'notify' | 'allow';
type ContentFilter = 'strict' | 'moderate' | 'off';

interface ChildSettings {
  dmPolicy: DmPolicy;
  contentFilter: ContentFilter;
}

function truncateKey(key: string): string {
  if (key.length <= 16) return key;
  return key.slice(0, 8) + '...' + key.slice(-8);
}

const dmPolicyOptions: { value: DmPolicy; label: string }[] = [
  { value: 'block_all', label: 'Block All' },
  { value: 'approve_only', label: 'Approve Only' },
  { value: 'notify', label: 'Notify' },
  { value: 'allow', label: 'Allow' },
];

const contentFilterOptions: { value: ContentFilter; label: string }[] = [
  { value: 'strict', label: 'Strict' },
  { value: 'moderate', label: 'Moderate' },
  { value: 'off', label: 'Off' },
];

export function GuardianControls({ identity, identities, onBack }: GuardianControlsProps) {
  const children = identities.filter((id) => id.guardianPubkey === identity.publicKey);

  const [childSettings, setChildSettings] = useState<Record<string, ChildSettings>>(() => {
    const initial: Record<string, ChildSettings> = {};
    for (const child of children) {
      initial[child.publicKey] = { dmPolicy: 'approve_only', contentFilter: 'strict' };
    }
    return initial;
  });

  const setDmPolicy = useCallback((childPubkey: string, policy: DmPolicy) => {
    setChildSettings((prev) => ({
      ...prev,
      [childPubkey]: { ...prev[childPubkey], dmPolicy: policy },
    }));
  }, []);

  const setContentFilter = useCallback((childPubkey: string, filter: ContentFilter) => {
    setChildSettings((prev) => ({
      ...prev,
      [childPubkey]: { ...prev[childPubkey], contentFilter: filter },
    }));
  }, []);

  const containerStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: 24,
    maxWidth: 480,
    margin: '0 auto',
    width: '100%',
    padding: '0 0 24px',
  };

  const sectionCardStyle: React.CSSProperties = {
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: 20,
    boxShadow: 'var(--shadow)',
  };

  const sectionTitleStyle: React.CSSProperties = {
    fontSize: 18,
    fontWeight: 700,
    color: 'var(--text-primary)',
    margin: '0 0 16px',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: 13,
    fontWeight: 600,
    color: 'var(--text-secondary)',
    marginBottom: 6,
  };

  return (
    <div style={containerStyle}>
      <h1
        style={{
          fontSize: 24,
          fontWeight: 700,
          color: 'var(--text-primary)',
          margin: 0,
        }}
      >
        Guardian Controls
      </h1>

      {/* ── My Children ────────────────────────────────────── */}
      <div style={sectionCardStyle}>
        <h2 style={sectionTitleStyle}>My Children</h2>

        {children.length === 0 ? (
          <p
            style={{
              fontSize: 14,
              color: 'var(--text-muted)',
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            No child accounts linked to this identity. Children must add your pubkey as their
            guardian during onboarding.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {children.map((child) => {
              const settings = childSettings[child.publicKey] ?? {
                dmPolicy: 'approve_only',
                contentFilter: 'strict',
              };
              return (
                <div
                  key={child.publicKey}
                  style={{
                    background: 'var(--bg-input)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: 16,
                  }}
                >
                  {/* Child identity info */}
                  <div style={{ marginBottom: 14 }}>
                    <div
                      style={{
                        fontSize: 15,
                        fontWeight: 700,
                        color: 'var(--text-primary)',
                        marginBottom: 4,
                      }}
                    >
                      {child.displayName}
                    </div>
                    <div
                      style={{
                        fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
                        fontSize: 12,
                        color: 'var(--text-muted)',
                        marginBottom: child.ageRange || child.entityType ? 8 : 0,
                      }}
                    >
                      {truncateKey(child.publicKey)}
                    </div>
                    {(child.ageRange || child.entityType) && (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {child.ageRange && (
                          <span
                            style={{
                              display: 'inline-block',
                              padding: '2px 10px',
                              borderRadius: 999,
                              fontSize: 11,
                              fontWeight: 600,
                              background: 'var(--warning)',
                              color: '#000',
                            }}
                          >
                            Age: {child.ageRange}
                          </span>
                        )}
                        {child.entityType && (
                          <span
                            style={{
                              display: 'inline-block',
                              padding: '2px 10px',
                              borderRadius: 999,
                              fontSize: 11,
                              fontWeight: 600,
                              background: 'var(--bg-card)',
                              border: '1px solid var(--border)',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {child.entityType.replace(/_/g, ' ')}
                          </span>
                        )}
                      </div>
                    )}
                  </div>

                  {/* DM Policy toggle */}
                  <div style={{ marginBottom: 14 }}>
                    <label style={labelStyle}>DM Policy</label>
                    <div
                      style={{
                        display: 'flex',
                        borderRadius: 999,
                        overflow: 'hidden',
                        border: '1px solid var(--border)',
                        background: 'var(--bg-card)',
                      }}
                      role="radiogroup"
                      aria-label="DM Policy"
                    >
                      {dmPolicyOptions.map((opt) => {
                        const isActive = settings.dmPolicy === opt.value;
                        return (
                          <button
                            key={opt.value}
                            role="radio"
                            aria-checked={isActive}
                            onClick={() => setDmPolicy(child.publicKey, opt.value)}
                            style={{
                              flex: 1,
                              height: 36,
                              border: 'none',
                              cursor: 'pointer',
                              fontSize: 12,
                              fontWeight: isActive ? 700 : 400,
                              background: isActive ? 'var(--accent)' : 'transparent',
                              color: isActive ? 'var(--accent-text)' : 'var(--text-secondary)',
                              transition: 'background 0.15s, color 0.15s',
                              WebkitTapHighlightColor: 'transparent',
                              padding: '0 4px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {opt.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Content Filter toggle */}
                  <div>
                    <label style={labelStyle}>Content Filter</label>
                    <div
                      style={{
                        display: 'flex',
                        borderRadius: 999,
                        overflow: 'hidden',
                        border: '1px solid var(--border)',
                        background: 'var(--bg-card)',
                      }}
                      role="radiogroup"
                      aria-label="Content Filter"
                    >
                      {contentFilterOptions.map((opt) => {
                        const isActive = settings.contentFilter === opt.value;
                        return (
                          <button
                            key={opt.value}
                            role="radio"
                            aria-checked={isActive}
                            onClick={() => setContentFilter(child.publicKey, opt.value)}
                            style={{
                              flex: 1,
                              height: 36,
                              border: 'none',
                              cursor: 'pointer',
                              fontSize: 13,
                              fontWeight: isActive ? 700 : 400,
                              background: isActive ? 'var(--accent)' : 'transparent',
                              color: isActive ? 'var(--accent-text)' : 'var(--text-secondary)',
                              transition: 'background 0.15s, color 0.15s',
                              WebkitTapHighlightColor: 'transparent',
                              padding: '0 8px',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {opt.label}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Back button ─────────────────────────────────────── */}
      <button
        className="btn btn-secondary"
        style={{ minHeight: 48 }}
        onClick={onBack}
      >
        Back
      </button>
    </div>
  );
}
