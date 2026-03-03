import { useState, useCallback } from 'react';
import type { StoredIdentity, StoredConnection } from '../lib/db';
import { parseQRPayload, computeSharedSecret, type QRPayload } from '../lib/signet';
import { useCamera } from '../hooks/useCamera';
import { useSignetWords } from '../hooks/useSignetWords';
import { QRScanner } from '../components/QRScanner';

interface ScanProps {
  identity: StoredIdentity;
  onConnect: (connection: Omit<StoredConnection, 'ownerPubkey'>) => Promise<void>;
}

type Step = 'scanner' | 'preview' | 'success';

interface ShareSelection {
  name: boolean;
  mobile: boolean;
  email: boolean;
  address: boolean;
}

export function Scan({ identity, onConnect }: ScanProps) {
  const [step, setStep] = useState<Step>('scanner');
  const [scannedPayload, setScannedPayload] = useState<QRPayload | null>(null);
  const [shareSelection, setShareSelection] = useState<ShareSelection>({
    name: true,
    mobile: false,
    email: false,
    address: false,
  });
  const [scanError, setScanError] = useState<string | null>(null);
  const [showPasteInput, setShowPasteInput] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [connecting, setConnecting] = useState(false);
  const [sharedSecret, setSharedSecret] = useState<string | null>(null);

  const { hasPermission, error: cameraError, requestPermission } = useCamera();
  const signetWords = useSignetWords(sharedSecret);

  // ── Handle QR scan ─────────────────────────────
  const handleScan = useCallback((data: string) => {
    try {
      const payload = parseQRPayload(data);
      setScannedPayload(payload);
      setScanError(null);
      setStep('preview');
    } catch {
      setScanError('Invalid QR code. Please scan a Signet QR code.');
    }
  }, []);

  // ── Handle paste fallback ──────────────────────
  const handlePasteSubmit = useCallback(() => {
    const text = pasteText.trim();
    if (!text) return;

    try {
      const payload = parseQRPayload(text);
      setScannedPayload(payload);
      setScanError(null);
      setShowPasteInput(false);
      setPasteText('');
      setStep('preview');
    } catch {
      setScanError('Invalid QR data. Please check the data and try again.');
    }
  }, [pasteText]);

  // ── Handle connect ─────────────────────────────
  const handleConnect = useCallback(async () => {
    if (!scannedPayload) return;

    setConnecting(true);
    try {
      const secret = computeSharedSecret(identity.privateKey, scannedPayload.pubkey);
      setSharedSecret(secret);

      const ourInfo: StoredConnection['ourInfo'] = {};
      if (shareSelection.name) ourInfo.name = identity.displayName;
      if (shareSelection.mobile) ourInfo.mobile = '';
      if (shareSelection.email) ourInfo.email = '';
      if (shareSelection.address) ourInfo.address = '';

      const connection: Omit<StoredConnection, 'ownerPubkey'> = {
        pubkey: scannedPayload.pubkey,
        sharedSecret: secret,
        theirInfo: scannedPayload.info ?? {},
        ourInfo,
        connectedAt: Math.floor(Date.now() / 1000),
        method: 'qr-scan',
      };

      await onConnect(connection);
      setStep('success');
    } catch {
      setScanError('Failed to establish connection. Please try again.');
    } finally {
      setConnecting(false);
    }
  }, [scannedPayload, identity, shareSelection, onConnect]);

  // ── Handle done / reset ────────────────────────
  const handleDone = useCallback(() => {
    setStep('scanner');
    setScannedPayload(null);
    setSharedSecret(null);
    setScanError(null);
    setShareSelection({ name: true, mobile: false, email: false, address: false });
  }, []);

  // ── Handle retry ───────────────────────────────
  const handleRetry = useCallback(() => {
    setScanError(null);
    setShowPasteInput(false);
    setPasteText('');
  }, []);

  // ── Styles ─────────────────────────────────────

  const containerStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    minHeight: '100%',
    width: '100%',
  };

  const headerStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    padding: '12px 16px',
    minHeight: 48,
    flexShrink: 0,
  };

  const backBtnStyle: React.CSSProperties = {
    background: 'none',
    border: 'none',
    fontSize: 24,
    color: 'var(--accent)',
    cursor: 'pointer',
    padding: '8px 12px 8px 0',
    minWidth: 44,
    minHeight: 44,
    display: 'flex',
    alignItems: 'center',
    WebkitTapHighlightColor: 'transparent',
  };

  const titleStyle: React.CSSProperties = {
    fontSize: 18,
    fontWeight: 700,
    color: 'var(--text-primary)',
  };

  // ── STEP 1: Scanner ────────────────────────────

  if (step === 'scanner') {
    // Camera permission not yet requested
    if (hasPermission === null) {
      return (
        <div style={containerStyle}>
          <div style={headerStyle}>
            <span style={titleStyle}>Scan QR Code</span>
          </div>
          <div
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: 24,
              gap: 16,
            }}
          >
            <div
              style={{
                width: 80,
                height: 80,
                borderRadius: '50%',
                background: 'var(--bg-card)',
                border: '2px solid var(--border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 36,
                marginBottom: 8,
              }}
            >
              {'\uD83D\uDCF7'}
            </div>
            <p
              style={{
                fontSize: 16,
                fontWeight: 600,
                color: 'var(--text-primary)',
                textAlign: 'center',
              }}
            >
              Camera Access Required
            </p>
            <p
              style={{
                fontSize: 14,
                color: 'var(--text-secondary)',
                textAlign: 'center',
                maxWidth: 300,
                lineHeight: 1.5,
              }}
            >
              Signet needs camera access to scan QR codes and connect with other users.
            </p>
            <button
              className="btn btn-primary"
              style={{ maxWidth: 280, marginTop: 8 }}
              onClick={requestPermission}
            >
              Allow Camera
            </button>
            <button
              className="btn btn-secondary"
              style={{ maxWidth: 280 }}
              onClick={() => setShowPasteInput(true)}
            >
              Paste QR Data Instead
            </button>
            {showPasteInput && renderPasteInput()}
          </div>
        </div>
      );
    }

    // Camera permission denied
    if (hasPermission === false) {
      return (
        <div style={containerStyle}>
          <div style={headerStyle}>
            <span style={titleStyle}>Scan QR Code</span>
          </div>
          <div
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: 24,
              gap: 16,
            }}
          >
            <div
              style={{
                width: 80,
                height: 80,
                borderRadius: '50%',
                background: 'var(--bg-card)',
                border: '2px solid var(--danger)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 36,
                marginBottom: 8,
              }}
            >
              {'\u26A0\uFE0F'}
            </div>
            <p
              style={{
                fontSize: 14,
                color: 'var(--danger)',
                textAlign: 'center',
                maxWidth: 300,
                lineHeight: 1.5,
              }}
            >
              {cameraError || 'Camera access was denied.'}
            </p>
            <button
              className="btn btn-primary"
              style={{ maxWidth: 280 }}
              onClick={requestPermission}
            >
              Try Again
            </button>
            <button
              className="btn btn-secondary"
              style={{ maxWidth: 280 }}
              onClick={() => setShowPasteInput(true)}
            >
              Paste QR Data Instead
            </button>
            {showPasteInput && renderPasteInput()}
          </div>
        </div>
      );
    }

    // Camera permission granted — show scanner
    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <span style={titleStyle}>Scan QR Code</span>
        </div>

        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            padding: '0 16px 16px',
            gap: 12,
            minHeight: 0,
          }}
        >
          <div
            style={{
              flex: 1,
              minHeight: 200,
              borderRadius: 'var(--radius)',
              overflow: 'hidden',
              position: 'relative',
            }}
          >
            <QRScanner onScan={handleScan} active={step === 'scanner' && hasPermission === true} />
          </div>

          {scanError && (
            <div
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--danger)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
              }}
            >
              <p style={{ fontSize: 13, color: 'var(--danger)', margin: 0 }}>
                {scanError}
              </p>
              <button
                onClick={handleRetry}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--accent)',
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: 'pointer',
                  padding: '4px 8px',
                  whiteSpace: 'nowrap',
                  minHeight: 44,
                  WebkitTapHighlightColor: 'transparent',
                }}
              >
                Dismiss
              </button>
            </div>
          )}

          <button
            className="btn btn-secondary"
            onClick={() => setShowPasteInput(!showPasteInput)}
          >
            Paste QR Data
          </button>

          {showPasteInput && renderPasteInput()}
        </div>
      </div>
    );
  }

  // ── STEP 2: Preview + Select ────────────────────

  if (step === 'preview' && scannedPayload) {
    const theirInfo = scannedPayload.info ?? {};
    const theirName = theirInfo.name || 'Unknown';

    const checkboxItems: { key: keyof ShareSelection; label: string }[] = [
      { key: 'name', label: 'Name' },
      { key: 'mobile', label: 'Mobile' },
      { key: 'email', label: 'Email' },
      { key: 'address', label: 'Address' },
    ];

    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <button
            style={backBtnStyle}
            onClick={() => {
              setStep('scanner');
              setScannedPayload(null);
              setScanError(null);
            }}
            aria-label="Back"
          >
            &#8592;
          </button>
          <span style={titleStyle}>New Connection</span>
        </div>

        <div
          style={{
            flex: 1,
            padding: '0 24px 24px',
            display: 'flex',
            flexDirection: 'column',
            gap: 24,
          }}
        >
          {/* Their info card */}
          <div
            style={{
              background: 'var(--bg-card)',
              borderRadius: 'var(--radius)',
              border: '1px solid var(--border)',
              padding: 20,
              boxShadow: 'var(--shadow)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 14,
                marginBottom: 16,
              }}
            >
              <div
                style={{
                  width: 48,
                  height: 48,
                  borderRadius: '50%',
                  background: 'var(--accent)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 20,
                  color: 'var(--accent-text)',
                  fontWeight: 700,
                  flexShrink: 0,
                }}
              >
                {theirName.charAt(0).toUpperCase()}
              </div>
              <div>
                <div
                  style={{
                    fontSize: 18,
                    fontWeight: 700,
                    color: 'var(--text-primary)',
                  }}
                >
                  {theirName}
                </div>
                <div
                  style={{
                    fontSize: 12,
                    color: 'var(--text-muted)',
                    fontFamily: 'monospace',
                    marginTop: 2,
                  }}
                >
                  {scannedPayload.pubkey.substring(0, 16)}...
                </div>
              </div>
            </div>

            {/* Their shared info */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {theirInfo.name && (
                <InfoRow label="Name" value={theirInfo.name} />
              )}
              {theirInfo.mobile && (
                <InfoRow label="Mobile" value={theirInfo.mobile} />
              )}
              {theirInfo.email && (
                <InfoRow label="Email" value={theirInfo.email} />
              )}
              {theirInfo.address && (
                <InfoRow label="Address" value={theirInfo.address} />
              )}
            </div>
          </div>

          {/* Select what to share */}
          <div>
            <h3
              style={{
                fontSize: 16,
                fontWeight: 700,
                color: 'var(--text-primary)',
                marginBottom: 12,
              }}
            >
              Select what to share
            </h3>
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
              }}
            >
              {checkboxItems.map((item) => (
                <label
                  key={item.key}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '12px 16px',
                    background: 'var(--bg-card)',
                    borderRadius: 'var(--radius-sm)',
                    border: `1px solid ${shareSelection[item.key] ? 'var(--accent)' : 'var(--border)'}`,
                    cursor: 'pointer',
                    minHeight: 44,
                    transition: 'border-color 0.15s',
                    WebkitTapHighlightColor: 'transparent',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={shareSelection[item.key]}
                    onChange={(e) =>
                      setShareSelection((prev) => ({
                        ...prev,
                        [item.key]: e.target.checked,
                      }))
                    }
                    style={{
                      width: 20,
                      height: 20,
                      accentColor: 'var(--accent)',
                      flexShrink: 0,
                    }}
                  />
                  <span
                    style={{
                      fontSize: 15,
                      fontWeight: 500,
                      color: 'var(--text-primary)',
                    }}
                  >
                    {item.label}
                    {item.key === 'name' && (
                      <span
                        style={{
                          fontSize: 13,
                          color: 'var(--text-muted)',
                          marginLeft: 8,
                        }}
                      >
                        ({identity.displayName})
                      </span>
                    )}
                  </span>
                </label>
              ))}
            </div>
          </div>

          <div style={{ marginTop: 'auto' }}>
            {scanError && (
              <p
                style={{
                  fontSize: 13,
                  color: 'var(--danger)',
                  textAlign: 'center',
                  marginBottom: 12,
                }}
              >
                {scanError}
              </p>
            )}
            <button
              className="btn btn-primary"
              disabled={connecting}
              onClick={handleConnect}
            >
              {connecting ? 'Connecting...' : 'Connect'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── STEP 3: Success ─────────────────────────────

  if (step === 'success' && scannedPayload) {
    const successTheirInfo = scannedPayload.info ?? {};
    const theirName = successTheirInfo.name || 'Unknown';

    return (
      <div style={containerStyle}>
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 24,
            gap: 20,
          }}
        >
          {/* Success icon */}
          <div
            style={{
              width: 80,
              height: 80,
              borderRadius: '50%',
              background: 'var(--success)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 40,
              color: '#fff',
              marginBottom: 4,
            }}
          >
            {'\u2713'}
          </div>

          <h2
            style={{
              fontSize: 24,
              fontWeight: 700,
              color: 'var(--text-primary)',
              textAlign: 'center',
            }}
          >
            Connected!
          </h2>

          <p
            style={{
              fontSize: 16,
              color: 'var(--text-secondary)',
              textAlign: 'center',
            }}
          >
            You are now connected with <strong style={{ color: 'var(--text-primary)' }}>{theirName}</strong>
          </p>

          {/* Signet Words */}
          {signetWords.words.length > 0 && (
            <div
              style={{
                background: 'var(--bg-card)',
                borderRadius: 'var(--radius)',
                border: '1px solid var(--border)',
                padding: 20,
                width: '100%',
                maxWidth: 360,
                boxShadow: 'var(--shadow)',
              }}
            >
              <p
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: 'var(--text-secondary)',
                  textAlign: 'center',
                  marginBottom: 12,
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                }}
              >
                Signet Words
              </p>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  gap: 10,
                  flexWrap: 'wrap',
                }}
              >
                {signetWords.words.map((word, i) => (
                  <span
                    key={i}
                    style={{
                      fontSize: 18,
                      fontWeight: 700,
                      fontFamily: 'monospace',
                      color: 'var(--signet-word)',
                      padding: '6px 14px',
                      background: 'var(--bg-input)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    {word}
                  </span>
                ))}
              </div>
              <p
                style={{
                  fontSize: 12,
                  color: 'var(--text-muted)',
                  textAlign: 'center',
                  marginTop: 10,
                }}
              >
                Refreshes in {signetWords.expiresIn}s
              </p>
            </div>
          )}

          <button
            className="btn btn-primary"
            style={{ maxWidth: 280, marginTop: 12 }}
            onClick={handleDone}
          >
            Done
          </button>
        </div>
      </div>
    );
  }

  // ── Fallback ───────────────────────────────────
  return null;

  // ── Helper: paste input ────────────────────────
  function renderPasteInput() {
    return (
      <div
        style={{
          background: 'var(--bg-card)',
          borderRadius: 'var(--radius)',
          border: '1px solid var(--border)',
          padding: 16,
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
        }}
      >
        <label
          style={{
            fontSize: 14,
            fontWeight: 600,
            color: 'var(--text-primary)',
          }}
        >
          Paste QR data
        </label>
        <textarea
          className="input"
          value={pasteText}
          onChange={(e) => setPasteText(e.target.value)}
          placeholder="Paste the QR code data here..."
          rows={3}
          style={{
            resize: 'none',
            fontFamily: 'monospace',
            fontSize: 13,
          }}
        />
        {scanError && (
          <p style={{ fontSize: 13, color: 'var(--danger)', margin: 0 }}>
            {scanError}
          </p>
        )}
        <button
          className="btn btn-primary"
          disabled={!pasteText.trim()}
          onClick={handlePasteSubmit}
        >
          Submit
        </button>
      </div>
    );
  }
}

// ── Small helper component ───────────────────────

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', gap: 8, fontSize: 14 }}>
      <span
        style={{
          color: 'var(--text-muted)',
          minWidth: 60,
          fontWeight: 500,
        }}
      >
        {label}:
      </span>
      <span style={{ color: 'var(--text-primary)', wordBreak: 'break-word' }}>
        {value}
      </span>
    </div>
  );
}
