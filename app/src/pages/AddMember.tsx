import { useState } from 'react';
import { useCamera } from '../hooks/useCamera';
import { QRScanner } from '../components/QRScanner';
import { QRCode } from '../components/QRCode';
import { SignetWords } from '../components/SignetWords';
import { parseQRPayload, computeSharedSecret, serializeQRPayload, createQRPayload, getActivePubkey, getActivePrivateKey, getActiveDisplayName } from '../lib/signet';
import type { SignetIdentity, FamilyMember } from '../types';

interface Props {
  identity: SignetIdentity;
  onAddMember: (member: FamilyMember) => Promise<void>;
  onDone: () => void;
  wordCount?: number;
}

type Step = 'choose' | 'scan' | 'show-qr' | 'enter-id' | 'preview' | 'success';

export function AddMember({ identity, onAddMember, onDone, wordCount }: Props) {
  const { hasPermission, error: cameraError, requestPermission } = useCamera();
  const [step, setStep] = useState<Step>('choose');
  const [theirPubkey, setTheirPubkey] = useState('');
  const [theirName, setTheirName] = useState('');
  const [sharedSecret, setSharedSecret] = useState('');
  const [idInput, setIdInput] = useState('');
  const [error, setError] = useState('');

  const qrPayload = serializeQRPayload(
    createQRPayload(getActivePubkey(identity), { name: getActiveDisplayName(identity) })
  );

  const handleScan = (data: string) => {
    try {
      const payload = parseQRPayload(data);
      if (!payload?.pubkey) throw new Error('Invalid QR code');
      setTheirPubkey(payload.pubkey);
      setTheirName(payload.info?.name || 'Unknown');
      setStep('preview');
    } catch {
      setError('Could not read QR code. Please try again.');
    }
  };

  const handleIdSubmit = () => {
    const cleaned = idInput.trim();
    if (cleaned.length !== 64 || !/^[0-9a-f]+$/i.test(cleaned)) {
      setError('Please enter a valid 64-character Signet ID');
      return;
    }
    setTheirPubkey(cleaned);
    setTheirName('');
    setStep('preview');
  };

  const handleConfirm = async () => {
    const secret = computeSharedSecret(getActivePrivateKey(identity), theirPubkey);
    setSharedSecret(secret);
    await onAddMember({
      pubkey: theirPubkey,
      ownerPubkey: getActivePubkey(identity),
      displayName: theirName || 'Family member',
      sharedSecret: secret,
      verifiedAt: Math.floor(Date.now() / 1000),
    });
    setStep('success');
  };

  if (step === 'choose') {
    return (
      <div className="fade-in">
        <div className="section">
          <h2 style={{ marginBottom: 4 }}>In person?</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 12 }}>
            Scan their QR code, or show yours for them to scan.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button className="btn btn-primary" onClick={() => {
              if (hasPermission === null) requestPermission().then(() => setStep('scan'));
              else setStep('scan');
            }}>
              Scan their QR code
            </button>
            <button className="btn btn-secondary" onClick={() => setStep('show-qr')}>
              Show my QR code
            </button>
          </div>
        </div>

        <div className="section">
          <h2 style={{ marginBottom: 4 }}>Remote?</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 12 }}>
            For phone or video calls — enter their Signet ID.
          </p>
          <button className="btn btn-secondary" onClick={() => setStep('enter-id')}>
            Enter their Signet ID
          </button>
        </div>
      </div>
    );
  }

  if (step === 'scan') {
    return (
      <div className="fade-in">
        <h2 style={{ marginBottom: 16 }}>Scan their QR code</h2>
        {cameraError && (
          <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>
            {cameraError}
          </div>
        )}
        {error && (
          <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>
            {error}
          </div>
        )}
        <QRScanner onScan={handleScan} active={hasPermission === true} />
        {hasPermission === null && (
          <button className="btn btn-primary" onClick={requestPermission} style={{ marginTop: 16 }}>
            Allow camera access
          </button>
        )}
        <button className="btn btn-ghost" onClick={() => { setStep('choose'); setError(''); }} style={{ marginTop: 12 }}>
          Back
        </button>
      </div>
    );
  }

  if (step === 'show-qr') {
    return (
      <div className="fade-in" style={{ textAlign: 'center' }}>
        <h2 style={{ marginBottom: 8 }}>Show this to them</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 16 }}>
          Ask them to scan this QR code with their Signet app.
        </p>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
          <QRCode data={qrPayload} size={240} />
        </div>
        <button className="btn btn-ghost" onClick={() => setStep('choose')}>Back</button>
      </div>
    );
  }

  if (step === 'enter-id') {
    return (
      <div className="fade-in">
        <h2 style={{ marginBottom: 8 }}>Enter their Signet ID</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 16 }}>
          Ask them to copy their Signet ID and send it to you.
        </p>
        {error && (
          <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>
            {error}
          </div>
        )}
        <input
          className="input"
          placeholder="64-character Signet ID"
          value={idInput}
          onChange={e => setIdInput(e.target.value.trim())}
          autoFocus
        />
        <button className="btn btn-primary" onClick={handleIdSubmit} disabled={!idInput.trim()} style={{ marginTop: 16 }}>
          Continue
        </button>
        <button className="btn btn-ghost" onClick={() => { setStep('choose'); setError(''); }} style={{ marginTop: 8 }}>
          Back
        </button>
      </div>
    );
  }

  if (step === 'preview') {
    return (
      <div className="fade-in" style={{ textAlign: 'center' }}>
        <h2 style={{ marginBottom: 16 }}>Add to family?</h2>
        <div className="card" style={{ marginBottom: 24 }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: 4 }}>
            {theirName || 'Unknown person'}
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
            {theirPubkey.slice(0, 16)}...{theirPubkey.slice(-8)}
          </div>
        </div>
        {!theirName && (
          <div style={{ marginBottom: 16 }}>
            <input
              className="input"
              placeholder="What should we call them?"
              value={theirName}
              onChange={e => setTheirName(e.target.value)}
            />
          </div>
        )}
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary" onClick={handleConfirm} style={{ flex: 1 }}>
            Add to family
          </button>
          <button className="btn btn-secondary" onClick={() => { setStep('choose'); setError(''); }} style={{ flex: 1 }}>
            Cancel
          </button>
        </div>
      </div>
    );
  }

  if (step === 'success') {
    return (
      <div className="fade-in" style={{ textAlign: 'center' }}>
        <div className="checkmark-anim" style={{ fontSize: '3rem', marginBottom: 8 }}>&#10003;</div>
        <h2 style={{ marginBottom: 8 }}>{theirName || 'Family member'} added</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 24 }}>
          Use Signet Me below to verify it's really them.
        </p>
        {sharedSecret && <SignetWords sharedSecret={sharedSecret} myPubkey={getActivePubkey(identity)} theirPubkey={theirPubkey} wordCount={wordCount} />}
        <button className="btn btn-primary" onClick={onDone} style={{ marginTop: 16 }}>
          Done
        </button>
      </div>
    );
  }

  return null;
}
