import { useState } from 'react';
import type { FamilyIdentity, AppPreferences } from '../types';

interface Props {
  identity: FamilyIdentity;
  preferences: AppPreferences;
  onSetTheme: (theme: 'system' | 'light' | 'dark') => void;
  onDeleteIdentity: () => void;
  onOpenChildSettings: () => void;
  hasChildren: boolean;
}

export function Settings({ identity, preferences, onSetTheme, onDeleteIdentity, onOpenChildSettings, hasChildren }: Props) {
  const [showRecovery, setShowRecovery] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [copied, setCopied] = useState(false);

  return (
    <div className="fade-in">
      {/* Name */}
      <div className="card section">
        <div className="section-title">My Name</div>
        <div style={{ fontWeight: 600 }}>{identity.displayName}</div>
      </div>

      {/* Recovery Phrase */}
      <div className="card section">
        <div className="section-title">Recovery Phrase</div>
        {!showRecovery ? (
          <button className="btn btn-secondary" onClick={() => setShowRecovery(true)}>
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
            <button className="btn btn-ghost" onClick={() => setShowRecovery(false)}>
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

      {/* Certificate */}
      <div className="card section">
        <div className="section-title">Certificate</div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
          Install this certificate to trust HTTPS on your local network.
        </p>
        <a
          href="/signet.pem"
          download="signet.pem"
          className="btn btn-secondary"
          style={{ display: 'inline-block', textDecoration: 'none' }}
        >
          Download Certificate
        </a>
      </div>

      {/* Export */}
      <div className="card section">
        <div className="section-title">Export My Signet</div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
          Take your identity to another app.
        </p>
        <button className="btn btn-secondary" onClick={() => {
          const data = JSON.stringify({ mnemonic: identity.mnemonic, displayName: identity.displayName });
          const blob = new Blob([data], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'my-signet-backup.json';
          a.click();
          URL.revokeObjectURL(url);
        }}>
          Export backup
        </button>
      </div>

      {/* Delete */}
      <div className="section" style={{ marginTop: 32 }}>
        {!confirmDelete ? (
          <button className="btn btn-ghost" onClick={() => setConfirmDelete(true)} style={{ color: 'var(--danger)' }}>
            Delete My Signet
          </button>
        ) : (
          <div className="card" style={{ borderColor: 'var(--danger)' }}>
            <p style={{ marginBottom: 12, fontSize: '0.9rem' }}>
              This will permanently delete your identity from this device. Make sure you've saved your recovery phrase.
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
