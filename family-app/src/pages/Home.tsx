import type { FamilyIdentity } from '../types';
import { QRCode } from '../components/QRCode';
import { TrustBar } from '../components/TrustBar';
import { StatusBadge } from '../components/StatusBadge';
import { encodeNpub, serializeQRPayload, createQRPayload } from '../lib/signet';
import { useState } from 'react';

interface Props {
  identity: FamilyIdentity;
  familyCount: number;
}

export function Home({ identity, familyCount }: Props) {
  const [copied, setCopied] = useState(false);
  const npub = encodeNpub(identity.publicKey);
  const shortNpub = npub.slice(0, 12) + '...' + npub.slice(-8);

  const qrPayload = serializeQRPayload(
    createQRPayload(identity.publicKey, { name: identity.displayName })
  );

  const copyPubkey = () => {
    navigator.clipboard?.writeText(identity.publicKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Simple trust score: family members verified = basic trust
  const trustScore = Math.min(familyCount * 10 + 10, 200);

  return (
    <div className="fade-in">
      {/* Identity Card */}
      <div className="card section" style={{ textAlign: 'center' }}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
          <QRCode data={qrPayload} size={180} />
        </div>
        <h1 style={{ marginBottom: 4 }}>{identity.displayName}</h1>
        <StatusBadge isVerified={familyCount > 0} isChild={identity.isChild} />
      </div>

      {/* Trust Summary */}
      {!identity.isChild && (
        <div className="card section">
          <TrustBar score={trustScore} label="Signet IQ" />
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 12, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            <span>Family: {familyCount} member{familyCount !== 1 ? 's' : ''} verified</span>
            <span>Since {new Date(identity.createdAt * 1000).toLocaleDateString('en-GB', { month: 'short', year: 'numeric' })}</span>
          </div>
        </div>
      )}

      {/* Child info */}
      {identity.isChild && identity.guardianPubkey && (
        <div className="card section">
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Linked to parent:
          </div>
          <div style={{ fontSize: '0.85rem', fontFamily: 'monospace', marginTop: 4, wordBreak: 'break-all' }}>
            {identity.guardianPubkey.slice(0, 16)}...{identity.guardianPubkey.slice(-8)}
          </div>
        </div>
      )}

      {/* Signet ID */}
      <div className="card section">
        <div className="section-title">Your Signet ID</div>
        <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', wordBreak: 'break-all', marginBottom: 8 }}>
          {shortNpub}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-secondary" onClick={copyPubkey} style={{ flex: 1 }}>
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button className="btn btn-secondary" onClick={() => {
            navigator.share?.({ title: 'My Signet', text: identity.publicKey });
          }} style={{ flex: 1 }}>
            Share
          </button>
        </div>
      </div>
    </div>
  );
}
