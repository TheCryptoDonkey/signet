import { useState } from 'react';
import type { NostrConnectRequest } from '../lib/nip46';
import { sendConnectResponse } from '../lib/nip46';

interface Props {
  request: NostrConnectRequest;
  signerPrivateKey: string;
  signerPubkey: string;
  signerDisplayName: string;
  onDone: () => void;
}

export function ApproveConnect({ request, signerPrivateKey, signerPubkey, signerDisplayName, onDone }: Props) {
  const [status, setStatus] = useState<'pending' | 'sending' | 'sent' | 'error'>('pending');

  async function handleApprove() {
    setStatus('sending');
    try {
      const ok = await sendConnectResponse(request, signerPrivateKey, signerPubkey);
      setStatus(ok ? 'sent' : 'error');
      if (ok) setTimeout(onDone, 1500); // Brief success message before returning
    } catch (e) {
      console.error('NIP-46 send failed:', e);
      setStatus('error');
    }
  }

  return (
    <div className="fade-in" role="main">
      <div className="section">
        <h2 style={{ marginBottom: 8 }}>Connection Request</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
          <strong>{request.appName}</strong> wants to verify your identity.
        </p>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: 8 }}>
          Signing in as <strong>{signerDisplayName}</strong>
        </p>
      </div>

      <div className="card section">
        <div className="section-title">Connection details</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: '0.9rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>App: </span>
            <span style={{ fontWeight: 600 }}>{request.appName}</span>
          </div>
          {request.appUrl && (
            <div style={{ fontSize: '0.9rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>URL: </span>
              <span style={{ wordBreak: 'break-all' }}>{request.appUrl}</span>
            </div>
          )}
          <div style={{ fontSize: '0.85rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Relay: </span>
            <span style={{ wordBreak: 'break-all', color: 'var(--text-secondary)' }}>{request.relayUrl}</span>
          </div>
        </div>
      </div>

      {status === 'pending' && (
        <div className="section" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <button className="btn btn-primary" onClick={handleApprove}>
            Approve
          </button>
          <button className="btn btn-ghost" onClick={onDone}>
            Deny
          </button>
        </div>
      )}

      {status === 'sending' && (
        <div className="section" style={{ textAlign: 'center' }}>
          <p style={{ color: 'var(--text-secondary)' }}>Sending...</p>
        </div>
      )}

      {status === 'sent' && (
        <div className="section" style={{ textAlign: 'center' }}>
          <p style={{ color: 'var(--success, #22c55e)', fontWeight: 600 }}>Connected! Returning...</p>
        </div>
      )}

      {status === 'error' && (
        <div className="section" style={{ textAlign: 'center' }}>
          <p style={{ color: 'var(--danger, #ef4444)', marginBottom: 12 }}>Failed to connect. Try again?</p>
          <button className="btn btn-secondary" onClick={handleApprove}>
            Retry
          </button>
        </div>
      )}
    </div>
  );
}
