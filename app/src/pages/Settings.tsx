import { useState } from 'react';
import type { SignetIdentity, AppPreferences, SecurityTier } from '../types';
import { getActiveDisplayName } from '../lib/signet';

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
}

export function Settings({ identity, preferences, securityTier, onSetTheme, onSetSecurityTier, onDeleteIdentity, onOpenChildSettings, hasChildren }: Props) {
  const [showBackup, setShowBackup] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [copied, setCopied] = useState(false);

  return (
    <div className="fade-in">
      {/* Name */}
      <div className="card section">
        <div className="section-title">My Name</div>
        <div style={{ fontWeight: 600 }}>{getActiveDisplayName(identity)}</div>
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
            }}>
              {copied ? 'Copied!' : 'Copy to clipboard'}
            </button>
            <button className="btn btn-ghost" onClick={() => setShowBackup(false)}>
              Hide
            </button>
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
        <div>My Signet v1.0.0</div>
        <div>Open source identity verification</div>
      </div>
    </div>
  );
}
