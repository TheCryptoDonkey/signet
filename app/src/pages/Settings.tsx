import { useState, useEffect } from 'react';
import type { SignetIdentity, AppPreferences, SecurityTier } from '../types';
import { getActiveDisplayName, encodeNpub } from '../lib/signet';

const TIER_INFO: Record<SecurityTier, { label: string; description: string }> = {
  basic: { label: 'Basic', description: '1 word each — quick check' },
  standard: { label: 'Standard', description: '2 words each — approvals' },
  expert: { label: 'Expert', description: '3 words each — high security' },
};

interface Props {
  identity: SignetIdentity;
  preferences: AppPreferences;
  securityTier: SecurityTier;
  onSetTheme: (theme: 'system' | 'light' | 'dark') => void;
  onSetSecurityTier: (tier: SecurityTier) => void;
  onDeleteIdentity: () => void;
  onOpenChildSettings: () => void;
  hasChildren: boolean;
  powerMode: boolean;
  onSetPowerMode: (enabled: boolean) => void;
  onNavigateShamir: () => void;
  onNavigateBridge: () => void;
  onSwitchPrimary: (keypair: 'natural-person' | 'persona') => void;
}

export function Settings({ identity, preferences, securityTier, onSetTheme, onSetSecurityTier, onDeleteIdentity, onOpenChildSettings, hasChildren, powerMode, onSetPowerMode, onNavigateShamir, onNavigateBridge, onSwitchPrimary }: Props) {
  const [showBackup, setShowBackup] = useState(false);

  useEffect(() => {
    if (!showBackup) return;
    const timer = setTimeout(() => setShowBackup(false), 90000);
    return () => clearTimeout(timer);
  }, [showBackup]);

  const [confirmDelete, setConfirmDelete] = useState(false);
  const [copied, setCopied] = useState(false);
  const [relayUrl, setRelayUrl] = useState('wss://relay.damus.io');
  const [editingRelay, setEditingRelay] = useState(false);
  const [relayDraft, setRelayDraft] = useState('');
  const [versionTaps, setVersionTaps] = useState(0);

  let npNpub: string;
  let personaNpub: string;
  if (identity.naturalPerson.publicKey) {
    try { npNpub = encodeNpub(identity.naturalPerson.publicKey); } catch { npNpub = identity.naturalPerson.publicKey; }
  } else {
    npNpub = 'Not available (nsec import)';
  }
  if (identity.persona.publicKey) {
    try { personaNpub = encodeNpub(identity.persona.publicKey); } catch { personaNpub = identity.persona.publicKey; }
  } else {
    personaNpub = 'Not available (nsec import)';
  }

  function truncateNpub(npub: string): string {
    if (npub.length <= 20) return npub;
    return `${npub.slice(0, 10)}...${npub.slice(-8)}`;
  }

  function handleVersionTap() {
    const next = versionTaps + 1;
    setVersionTaps(next);
    if (next >= 5) {
      setVersionTaps(0);
      alert('Verifier mode activated!');
    }
  }

  return (
    <div className="fade-in" role="main">
      {/* Name */}
      <div className="card section">
        <div className="section-title">My Name</div>
        <div style={{ fontWeight: 600 }}>{getActiveDisplayName(identity)}</div>
      </div>

      {/* My Identity */}
      <div className="card section">
        <div className="section-title">My Identity</div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 12 }}>
          Switch which keypair is your primary identity.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {(['natural-person', 'persona'] as const).map(kp => {
            const isActive = identity.primaryKeypair === kp;
            const label = kp === 'natural-person' ? 'Natural Person' : 'Persona';
            const npub = kp === 'natural-person' ? npNpub : personaNpub;
            return (
              <button
                key={kp}
                className={`btn ${isActive ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => !isActive && onSwitchPrimary(kp)}
                style={{ padding: '10px 16px', textAlign: 'left', justifyContent: 'flex-start' }}
              >
                <div>
                  <div style={{ fontWeight: 600 }}>{label}{isActive ? ' (active)' : ''}</div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 400, opacity: 0.8, fontFamily: 'monospace' }}>{truncateNpub(npub)}</div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Verification Security */}
      <div className="card section">
        <div className="section-title">Verification Security</div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 12 }}>
          How many words each person says during Signet Me. More words = harder to guess.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {(['basic', 'standard', 'expert'] as const).map(tier => (
            <button
              key={tier}
              className={`btn ${securityTier === tier ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => onSetSecurityTier(tier)}
              style={{ padding: '10px 16px', textAlign: 'left', justifyContent: 'flex-start' }}
            >
              <div>
                <div style={{ fontWeight: 600 }}>{TIER_INFO[tier].label}</div>
                <div style={{ fontSize: '0.8rem', fontWeight: 400, opacity: 0.8 }}>{TIER_INFO[tier].description}</div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Backup Words */}
      <div className="card section">
        <div className="section-title">Backup Words</div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
          These 12 words are the only way to recover your Signet on a new device.
        </p>
        {!showBackup ? (
          <button className="btn btn-secondary" onClick={() => setShowBackup(true)}>
            View my 12 words
          </button>
        ) : (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 12 }}>
              {identity.mnemonic.split(' ').map((word, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '4px 0' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', width: 20, textAlign: 'right' }}>{i + 1}</span>
                  <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{word}</span>
                </div>
              ))}
            </div>
            <button className="btn btn-ghost" onClick={() => {
              navigator.clipboard?.writeText(identity.mnemonic);
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
              // Clear clipboard after 60 seconds
              setTimeout(() => navigator.clipboard?.writeText(''), 60_000);
            }}>
              {copied ? 'Copied!' : 'Copy to clipboard'}
            </button>
            <button className="btn btn-ghost" onClick={() => setShowBackup(false)}>
              Hide
            </button>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 8 }}>
              Words auto-hide after 90 seconds. Clipboard clears after 60 seconds.
            </p>
          </div>
        )}
      </div>

      {/* Appearance */}
      <div className="card section">
        <div className="section-title">Appearance</div>
        <div style={{ display: 'flex', gap: 8 }}>
          {(['system', 'light', 'dark'] as const).map(theme => (
            <button
              key={theme}
              className={`btn ${preferences.theme === theme ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => onSetTheme(theme)}
              style={{ flex: 1, padding: '8px 12px', fontSize: '0.85rem' }}
            >
              {theme.charAt(0).toUpperCase() + theme.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Power Mode */}
      <div className="card section">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <div className="section-title" style={{ marginBottom: 0 }}>Power Mode</div>
          <button
            onClick={() => onSetPowerMode(!powerMode)}
            style={{
              width: 48,
              height: 28,
              borderRadius: 14,
              background: powerMode ? 'var(--accent, #6366f1)' : 'var(--border)',
              border: 'none',
              cursor: 'pointer',
              position: 'relative',
              transition: 'background 0.2s',
              flexShrink: 0,
            }}
            aria-label={powerMode ? 'Disable Power Mode' : 'Enable Power Mode'}
          >
            <span
              style={{
                position: 'absolute',
                top: 3,
                left: powerMode ? 23 : 3,
                width: 22,
                height: 22,
                borderRadius: '50%',
                background: '#fff',
                transition: 'left 0.2s',
                display: 'block',
              }}
            />
          </button>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 0 }}>
          Show advanced features like Signet IQ breakdown, identity bridge, and relay settings.
        </p>
      </div>

      {/* Power mode: Shamir Backup */}
      {powerMode && (
        <div className="card section">
          <div className="section-title">Shamir Backup</div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
            Split your backup between trusted people so no single person can access your account.
          </p>
          <button className="btn btn-secondary" onClick={onNavigateShamir}>
            Manage Shamir Backup
          </button>
        </div>
      )}

      {/* Power mode: Identity Bridge */}
      {powerMode && (
        <div className="card section">
          <div className="section-title">Identity Bridge</div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
            Link your real and anonymous identities with a ring signature proof.
          </p>
          <button className="btn btn-secondary" onClick={onNavigateBridge}>
            Open Identity Bridge
          </button>
        </div>
      )}

      {/* Power mode: Relay */}
      {powerMode && (
        <div className="card section">
          <div className="section-title">Relay</div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
            Current relay used for publishing and fetching Signet events.
          </p>
          {!editingRelay ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ flex: 1, fontSize: '0.85rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{relayUrl}</span>
              <button className="btn btn-secondary" onClick={() => { setRelayDraft(relayUrl); setEditingRelay(true); }} style={{ flexShrink: 0 }}>
                Edit
              </button>
            </div>
          ) : (
            <div>
              <input
                className="input"
                value={relayDraft}
                onChange={e => setRelayDraft(e.target.value)}
                placeholder="wss://relay.example.com"
                autoFocus
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                <button className="btn btn-primary" onClick={() => { setRelayUrl(relayDraft.trim()); setEditingRelay(false); }} disabled={!relayDraft.trim()} style={{ flex: 1 }}>
                  Save
                </button>
                <button className="btn btn-ghost" onClick={() => setEditingRelay(false)} style={{ flex: 1 }}>
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Child Accounts */}
      {hasChildren && (
        <div className="card section">
          <div className="section-title">Child Accounts</div>
          <button className="btn btn-secondary" onClick={onOpenChildSettings}>
            Manage linked children
          </button>
        </div>
      )}

      {/* Delete */}
      <div className="section" style={{ marginTop: 32 }}>
        {!confirmDelete ? (
          <button className="btn btn-ghost" onClick={() => setConfirmDelete(true)} style={{ color: 'var(--danger)' }}>
            Delete My Signet
          </button>
        ) : (
          <div className="card" style={{ borderColor: 'var(--danger)' }}>
            <p style={{ marginBottom: 12, fontSize: '0.9rem' }}>
              This will permanently delete your identity from this device. Make sure you've saved your backup words.
            </p>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-danger" onClick={onDeleteIdentity} style={{ flex: 1 }}>Delete forever</button>
              <button className="btn btn-secondary" onClick={() => setConfirmDelete(false)} style={{ flex: 1 }}>Cancel</button>
            </div>
          </div>
        )}
      </div>

      {/* About */}
      <div style={{ textAlign: 'center', marginTop: 32, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
        <div
          onClick={handleVersionTap}
          style={{ cursor: 'pointer', userSelect: 'none', padding: '4px 0' }}
        >
          My Signet v1.0.0
        </div>
        <div>Open source identity verification</div>
      </div>
    </div>
  );
}
