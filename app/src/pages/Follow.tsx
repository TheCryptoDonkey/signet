import { useState, useCallback } from 'react';
import { ENTITY_LABELS, decodeNpub } from '../lib/signet';
import { fetchBadge } from '../lib/badge-fetch';
import type { StoredConnection, StoredIdentity, CachedBadge } from '../lib/db';

interface FollowProps {
  identity: StoredIdentity;
  onConnect: (connection: Omit<StoredConnection, 'ownerPubkey'>) => Promise<void>;
  onBack: () => void;
  relayUrl?: string;
}

type Step = 'input' | 'preview' | 'success';

function isValidHexPubkey(s: string): boolean {
  return /^[0-9a-f]{64}$/i.test(s);
}

export function Follow({ identity, onConnect, onBack, relayUrl }: FollowProps) {
  const [step, setStep] = useState<Step>('input');
  const [pubkeyInput, setPubkeyInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [badge, setBadge] = useState<CachedBadge | null>(null);
  const [resolvedPubkey, setResolvedPubkey] = useState('');

  const handleLookup = useCallback(async () => {
    const trimmed = pubkeyInput.trim();
    let hex = trimmed;

    if (trimmed.startsWith('npub')) {
      try {
        hex = decodeNpub(trimmed);
      } catch {
        setError('Invalid npub format');
        return;
      }
    }

    if (!isValidHexPubkey(hex)) {
      setError('Enter a valid 64-character hex pubkey or npub');
      return;
    }

    if (hex === identity.publicKey) {
      setError("That's your own pubkey");
      return;
    }

    setError('');
    setLoading(true);
    setResolvedPubkey(hex);

    if (relayUrl) {
      const fetched = await fetchBadge(hex, relayUrl);
      setBadge(fetched);
    }

    setStep('preview');
    setLoading(false);
  }, [pubkeyInput, relayUrl, identity.publicKey]);

  const handleFollow = useCallback(async () => {
    setLoading(true);
    const connection: Omit<StoredConnection, 'ownerPubkey'> = {
      pubkey: resolvedPubkey,
      sharedSecret: '',
      theirInfo: {},
      ourInfo: {},
      connectedAt: Math.floor(Date.now() / 1000),
      method: 'pubkey-lookup',
      connectionType: 'follow',
      badge: badge ?? undefined,
    };
    await onConnect(connection);
    setStep('success');
    setLoading(false);
  }, [resolvedPubkey, badge, onConnect]);

  if (step === 'success') {
    return (
      <div style={{ textAlign: 'center', padding: '40px 20px' }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>&#10003;</div>
        <h2 style={{ marginBottom: 8 }}>Following</h2>
        <p style={{ color: 'var(--text-muted)', marginBottom: 24 }}>
          {resolvedPubkey.slice(0, 8)}...{resolvedPubkey.slice(-8)}
        </p>
        <button className="btn btn-primary" onClick={onBack} style={{ width: '100%', maxWidth: 320 }}>
          Done
        </button>
      </div>
    );
  }

  if (step === 'preview') {
    const truncated = resolvedPubkey.slice(0, 8) + '...' + resolvedPubkey.slice(-8);
    return (
      <div style={{ maxWidth: 480, margin: '0 auto', padding: '0 16px' }}>
        <button
          onClick={() => setStep('input')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', marginBottom: 16, padding: 0 }}
        >
          &larr; Back
        </button>

        <div className="card" style={{ padding: 20, marginBottom: 16 }}>
          <div style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12 }}>
            {truncated}
          </div>

          {badge ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Tier</span>
                <span style={{ fontWeight: 600 }}>{badge.tierLabel} ({badge.tier})</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Signet IQ</span>
                <span style={{ fontWeight: 600 }}>{badge.score}</span>
              </div>
              {badge.entityType && (
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>Entity type</span>
                  <span style={{ fontWeight: 600 }}>
                    {ENTITY_LABELS[badge.entityType] ?? badge.entityType}
                  </span>
                </div>
              )}
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Credentials</span>
                <span>{badge.credentialCount}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Vouches</span>
                <span>{badge.vouchCount}</span>
              </div>
              {!badge.isVerified && badge.vouchCount === 0 && (
                <div style={{ color: 'var(--warning)', fontSize: 13, marginTop: 4 }}>
                  No credentials or vouches found on relay
                </div>
              )}
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>
              {relayUrl ? 'No badge data found on relay' : 'No relay configured \u2014 badge data unavailable'}
            </div>
          )}
        </div>

        <button
          className="btn btn-primary"
          onClick={handleFollow}
          disabled={loading}
          style={{ width: '100%', minHeight: 48 }}
        >
          {loading ? 'Following...' : 'Follow'}
        </button>
      </div>
    );
  }

  // step === 'input'
  return (
    <div style={{ maxWidth: 480, margin: '0 auto', padding: '0 16px' }}>
      <button
        onClick={onBack}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', marginBottom: 16, padding: 0 }}
      >
        &larr; Back
      </button>

      <h2 style={{ marginBottom: 8 }}>Follow a pubkey</h2>
      <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 20 }}>
        Enter an npub or hex pubkey to follow someone publicly. No mutual exchange needed.
      </p>

      <textarea
        value={pubkeyInput}
        onChange={(e) => { setPubkeyInput(e.target.value); setError(''); }}
        placeholder="npub1... or 64-char hex"
        rows={3}
        style={{
          width: '100%',
          padding: 12,
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border-subtle)',
          background: 'var(--bg-input)',
          color: 'var(--text-primary)',
          fontFamily: 'monospace',
          fontSize: 13,
          resize: 'none',
          marginBottom: 8,
          boxSizing: 'border-box',
        }}
      />

      {error && (
        <div style={{ color: 'var(--danger)', fontSize: 13, marginBottom: 8 }}>{error}</div>
      )}

      <button
        className="btn btn-primary"
        onClick={handleLookup}
        disabled={loading || !pubkeyInput.trim()}
        style={{ width: '100%', minHeight: 48 }}
      >
        {loading ? 'Looking up...' : 'Look up'}
      </button>
    </div>
  );
}
