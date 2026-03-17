import type { SignetIdentity, FamilyMember, StoredCredential } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { encodeNpub, getActivePubkey, getActiveDisplayName } from '../lib/signet';
import { useState } from 'react';

interface Props {
  identity: SignetIdentity;
  members: FamilyMember[];
  credentials: StoredCredential[];
  onSelectMember: (pubkey: string) => void;
  onNavigateAdd: () => void;
  onNavigateGetVerified: () => void;
  onNavigateDocuments: () => void;
  onSelectCredential: (cred: StoredCredential) => void;
}

export function Home({ identity, members, credentials, onSelectMember, onNavigateAdd, onNavigateGetVerified, onNavigateDocuments: _onNavigateDocuments, onSelectCredential: _onSelectCredential }: Props) {
  const [copied, setCopied] = useState(false);
  const activePubkey = getActivePubkey(identity);
  const npub = encodeNpub(activePubkey);
  const shortNpub = npub.slice(0, 12) + '...' + npub.slice(-8);

  const copyPubkey = () => {
    navigator.clipboard?.writeText(activePubkey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Derive credential-based badge state
  const hasConfirmed = credentials.some(c => c.verifierStatus === 'confirmed');
  const hasPending = credentials.length > 0 && credentials.every(c => c.verifierStatus === 'pending');
  const credentialStatus: 'confirmed' | 'pending' | null = hasConfirmed ? 'confirmed' : hasPending ? 'pending' : null;

  return (
    <div className="fade-in" role="main">
      {/* Greeting */}
      <div className="section" style={{ marginBottom: 20 }}>
        <h1 style={{ marginBottom: 4 }}>{getActiveDisplayName(identity)}</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <StatusBadge isVerified={credentialStatus === 'confirmed' || members.length > 0} credentialStatus={credentialStatus} isChild={identity.isChild} />
          {identity.isChild && identity.guardianPubkey && (
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Linked to parent
            </span>
          )}
        </div>
      </div>

      {/* Family Members — the heart of the app */}
      {members.length > 0 ? (
        <div className="section">
          <div className="section-title">My Family</div>
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            {members.map((member, i) => (
              <button
                key={member.pubkey}
                onClick={() => onSelectMember(member.pubkey)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  width: '100%',
                  padding: '14px 16px',
                  background: 'none',
                  border: 'none',
                  borderBottom: i < members.length - 1 ? '1px solid var(--border)' : 'none',
                  cursor: 'pointer',
                  textAlign: 'left',
                  color: 'var(--text-primary)',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, marginBottom: 2 }}>{member.displayName}</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Tap to verify
                  </div>
                </div>
                <StatusBadge isVerified={true} isChild={member.isChild} />
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="card section" style={{ textAlign: 'center', padding: 32 }}>
          <h2 style={{ marginBottom: 8 }}>Add your first family member</h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 16, fontSize: '0.9rem' }}>
            Once connected, you can verify each other with Signet Me.
          </p>
          <button className="btn btn-primary" onClick={onNavigateAdd}>
            Add someone
          </button>
        </div>
      )}

      {/* Backup reminder — only when not backed up and has family members */}
      {!identity.backedUp && members.length > 0 && (
        <div className="card section" style={{ background: 'var(--warning-light, #fff8e1)', borderColor: 'var(--warning, #f9a825)' }}>
          <div style={{ marginBottom: 8, fontSize: '0.9rem' }}>
            Your account isn't backed up. If you lose this phone, you'll lose your connections.
          </div>
          <button className="btn btn-secondary" onClick={onNavigateGetVerified}>
            Back up now
          </button>
        </div>
      )}

      {/* How verification works */}
      <div
        className="card section"
        style={{ border: '1px dashed var(--border)', background: 'none', cursor: 'pointer' }}
        onClick={onNavigateGetVerified}
        role="button"
        tabIndex={0}
        onKeyDown={e => e.key === 'Enter' && onNavigateGetVerified()}
      >
        <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          How verification works →
        </div>
      </div>

      {/* Signet ID — small, at bottom */}
      <div className="card section">
        <div className="section-title">Your Signet ID</div>
        <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', wordBreak: 'break-all', marginBottom: 8, color: 'var(--text-secondary)' }}>
          {shortNpub}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-secondary" onClick={copyPubkey} style={{ flex: 1 }}>
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button className="btn btn-secondary" onClick={() => {
            navigator.share?.({ title: 'My Signet', text: activePubkey });
          }} style={{ flex: 1 }}>
            Share
          </button>
        </div>
      </div>
    </div>
  );
}
