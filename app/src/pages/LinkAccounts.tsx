import { useState, useCallback, useMemo } from 'react';
import {
  createIdentityBridge,
  selectDecoyRing,
  SIGNET_KINDS,
  MIN_BRIDGE_RING_SIZE,
  type NostrEvent,
  type SignetTier,
} from 'signet-protocol';
import type { StoredIdentity } from '../lib/db';

interface RelayHook {
  state: string;
  publish: (event: NostrEvent) => Promise<{ ok: boolean; message: string }>;
  fetch: (filters: import('signet-protocol').NostrFilter[]) => Promise<NostrEvent[]>;
  connect: () => Promise<void>;
}

interface LinkAccountsProps {
  identity: StoredIdentity;
  identities: StoredIdentity[];
  relay: RelayHook;
  onBack: () => void;
}

function truncateKey(key: string): string {
  if (key.length <= 16) return key;
  return key.slice(0, 8) + '...' + key.slice(-4);
}

export function LinkAccounts({ identity, identities, relay, onBack }: LinkAccountsProps) {
  const [anonPubkey, setAnonPubkey] = useState(identity.publicKey);
  const [realPubkey, setRealPubkey] = useState('');
  const [status, setStatus] = useState<'idle' | 'querying' | 'creating' | 'success' | 'error'>('idle');
  const [error, setError] = useState<string | null>(null);
  const [ringSize, setRingSize] = useState<number>(0);

  // Filter: account with mnemonic can be "real", account without (or nsec) can be "anon"
  const realCandidates = useMemo(() =>
    identities.filter((id) => id.publicKey !== anonPubkey),
  [identities, anonPubkey]);

  const handleLink = useCallback(async () => {
    if (!realPubkey) return;
    setStatus('querying');
    setError(null);

    try {
      // Get the real account's private key
      const realAccount = identities.find((id) => id.publicKey === realPubkey);
      const anonAccount = identities.find((id) => id.publicKey === anonPubkey);
      if (!realAccount || !anonAccount) {
        throw new Error('Account not found');
      }

      // Connect to relay if needed
      if (relay.state !== 'connected') {
        await relay.connect();
      }

      // Query relay for verified pubkeys to form the ring
      const credentials = await relay.fetch([
        { kinds: [SIGNET_KINDS.CREDENTIAL], limit: 100 },
      ]);

      // Extract unique verified pubkeys (subjects of credentials)
      const verifiedPubkeys = new Set<string>();
      for (const cred of credentials) {
        const dTag = cred.tags.find(t => t[0] === 'd')?.[1];
        if (dTag) verifiedPubkeys.add(dTag);
      }

      // Find minimum tier among ring candidates
      const ringMinTier: SignetTier = 3; // Default to tier 3

      if (verifiedPubkeys.size < MIN_BRIDGE_RING_SIZE - 1) {
        throw new Error(
          `Not enough verified accounts on relay for ring. Need at least ${MIN_BRIDGE_RING_SIZE} verified pubkeys, found ${verifiedPubkeys.size}. ` +
          `Ask ${MIN_BRIDGE_RING_SIZE - 1 - verifiedPubkeys.size} more verified users to publish credentials to the relay.`
        );
      }

      // Build the ring
      const candidateArray = Array.from(verifiedPubkeys);
      const actualRingSize = Math.min(candidateArray.length + 1, Math.max(MIN_BRIDGE_RING_SIZE, 10));
      const { ring, signerIndex } = selectDecoyRing(candidateArray, realPubkey, actualRingSize);
      setRingSize(ring.length);

      setStatus('creating');

      // Create and publish the bridge
      const bridgeEvent = await createIdentityBridge(
        anonAccount.privateKey,
        realAccount.privateKey,
        ring,
        signerIndex,
        ringMinTier,
      );

      const result = await relay.publish(bridgeEvent);
      if (!result.ok) {
        throw new Error(`Relay rejected: ${result.message}`);
      }

      setStatus('success');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create bridge');
      setStatus('error');
    }
  }, [realPubkey, anonPubkey, identities, relay]);

  const containerStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    maxWidth: 480,
    margin: '0 auto',
    width: '100%',
    padding: '0 16px 32px',
  };

  return (
    <div style={containerStyle}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 20, minHeight: 44 }}>
        <button
          onClick={onBack}
          aria-label="Back"
          style={{
            background: 'none', border: 'none', fontSize: 24, color: 'var(--accent)',
            cursor: 'pointer', padding: '8px 12px 8px 0', minWidth: 44, minHeight: 44,
            display: 'flex', alignItems: 'center', WebkitTapHighlightColor: 'transparent',
          }}
        >
          &#8592;
        </button>
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
          Link Accounts
        </h1>
      </div>

      <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 24, lineHeight: 1.5 }}>
        Create a cryptographic bridge between your verified real-name account and an anonymous account.
        A ring signature proves your anon account is backed by a verified identity without revealing which one.
      </p>

      {status === 'success' ? (
        <div
          className="card"
          style={{ padding: 24, textAlign: 'center' }}
        >
          <div style={{ fontSize: 48, marginBottom: 16 }}>&#128279;</div>
          <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--success)', marginBottom: 8 }}>
            Accounts Linked
          </h2>
          <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 8 }}>
            Ring signature published with {ringSize} members.
          </p>
          <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            Your anonymous account now has bridge trust points.
          </p>
          <button
            className="btn btn-primary"
            style={{ marginTop: 20 }}
            onClick={onBack}
          >
            Done
          </button>
        </div>
      ) : (
        <>
          {/* Anonymous account selector */}
          <div style={{ marginBottom: 20 }}>
            <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: 8 }}>
              Anonymous Account (publishes the bridge)
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {identities.map((id) => (
                <button
                  key={id.publicKey}
                  onClick={() => { setAnonPubkey(id.publicKey); setRealPubkey(''); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '10px 14px',
                    background: anonPubkey === id.publicKey ? 'var(--bg-input)' : 'var(--bg-card)',
                    border: `1px solid ${anonPubkey === id.publicKey ? 'var(--accent)' : 'var(--border)'}`,
                    borderRadius: 'var(--radius-sm)',
                    cursor: 'pointer', minHeight: 44, width: '100%', textAlign: 'left',
                    WebkitTapHighlightColor: 'transparent',
                  }}
                >
                  <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', flex: 1 }}>
                    {id.displayName}
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                    {truncateKey(id.publicKey)}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Verified account selector */}
          <div style={{ marginBottom: 20 }}>
            <label style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: 8 }}>
              Verified Account (signs the ring signature)
            </label>
            {realCandidates.length === 0 ? (
              <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                You need at least 2 accounts to create a bridge.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {realCandidates.map((id) => (
                  <button
                    key={id.publicKey}
                    onClick={() => setRealPubkey(id.publicKey)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '10px 14px',
                      background: realPubkey === id.publicKey ? 'var(--bg-input)' : 'var(--bg-card)',
                      border: `1px solid ${realPubkey === id.publicKey ? 'var(--accent)' : 'var(--border)'}`,
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer', minHeight: 44, width: '100%', textAlign: 'left',
                      WebkitTapHighlightColor: 'transparent',
                    }}
                  >
                    <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', flex: 1 }}>
                      {id.displayName}
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      {truncateKey(id.publicKey)}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {error && (
            <div
              style={{
                padding: '10px 14px',
                background: 'var(--danger)',
                color: '#fff',
                borderRadius: 'var(--radius-sm)',
                fontSize: 13,
                marginBottom: 16,
                lineHeight: 1.4,
              }}
            >
              {error}
            </div>
          )}

          <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.5 }}>
            Requires at least {MIN_BRIDGE_RING_SIZE} verified pubkeys on the relay to form an anonymity ring.
            {relay.state !== 'connected' && (
              <span style={{ color: 'var(--danger)' }}> Relay not connected.</span>
            )}
          </div>

          <button
            className="btn btn-primary"
            style={{ width: '100%', minHeight: 48 }}
            disabled={!realPubkey || !anonPubkey || status === 'querying' || status === 'creating' || relay.state !== 'connected'}
            onClick={handleLink}
          >
            {status === 'querying' ? 'Querying relay...' : status === 'creating' ? 'Creating bridge...' : 'Create Identity Bridge'}
          </button>
        </>
      )}
    </div>
  );
}
