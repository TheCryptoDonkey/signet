import { useState, useRef, useCallback } from 'react';
import { Html5Qrcode } from 'html5-qrcode';
import { QRScanner } from '../components/QRScanner';
import { useCamera } from '../hooks/useCamera';
import type { VerifyRequest } from '../lib/presentation';
import { routeQR } from '../lib/qr-router';
import type { AuthRequest, LoginRequest } from '../lib/qr-router';

interface Props {
  onVerifyRequest: (request: VerifyRequest) => void;
  onAuthRequest: (request: AuthRequest) => void;
  onLoginRequest: (request: LoginRequest) => void;
  onBack: () => void;
}

async function decodeQRFromImage(file: File): Promise<string> {
  const html5QrCode = new Html5Qrcode('qr-reader-hidden');
  const result = await html5QrCode.scanFileV2(file, false);
  return result.decodedText;
}

export function WebVerify({ onVerifyRequest, onAuthRequest, onLoginRequest, onBack }: Props) {
  const [scannerActive, setScannerActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [decoding, setDecoding] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { hasPermission, error: cameraError, requestPermission } = useCamera();

  const handleQRData = useCallback((data: string) => {
    setScannerActive(false);
    const action = routeQR(data);
    switch (action.type) {
      case 'verify':
        setError(null);
        onVerifyRequest(action.request);
        break;
      case 'auth':
        setError(null);
        onAuthRequest(action.request);
        break;
      case 'login':
        setError(null);
        onLoginRequest(action.request);
        break;
      case 'contact':
        setError("This is a Nostr contact key, not a website verification. Use \"Add Family Member\" instead.");
        break;
      case 'nostr-connect':
        // Treat a raw nostr+connect URI as an auth request using the URI as the origin
        setError(null);
        onAuthRequest({
          type: 'signet-auth-request',
          requestId: '',
          challenge: '',
          origin: action.uri,
          relay: action.relay,
          timestamp: Math.floor(Date.now() / 1000),
        });
        break;
      case 'unknown':
        setError("This QR code isn't recognised by Signet.");
        break;
    }
  }, [onVerifyRequest, onAuthRequest, onLoginRequest]);

  const handleScanCamera = useCallback(async () => {
    setError(null);
    if (hasPermission === null || hasPermission === false) {
      await requestPermission();
    }
    setScannerActive(true);
  }, [hasPermission, requestPermission]);

  const handleFileChange = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    // Reset input so the same file can be re-selected if needed
    e.target.value = '';
    setError(null);
    setDecoding(true);
    try {
      const data = await decodeQRFromImage(file);
      handleQRData(data);
    } catch {
      setError("Couldn't read a QR code from that image. Try a clearer photo.");
    } finally {
      setDecoding(false);
    }
  }, [handleQRData]);

  const handleChoosePhoto = useCallback(() => {
    setError(null);
    setScannerActive(false);
    fileInputRef.current?.click();
  }, []);

  const handleCancelScan = useCallback(() => {
    setScannerActive(false);
    setError(null);
  }, []);

  return (
    <div className="fade-in" role="main">
      {/* Hidden div required by html5-qrcode for file scanning */}
      <div id="qr-reader-hidden" style={{ display: 'none' }} />

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        style={{ display: 'none' }}
        onChange={handleFileChange}
        aria-label="Choose image containing QR code"
      />

      {!scannerActive ? (
        <>
          <div className="section" style={{ marginBottom: 8 }}>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 24 }}>
              Scan or select a QR code from a website to verify your age or log in with Signet.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <button
                className="btn btn-primary"
                onClick={handleScanCamera}
                disabled={decoding}
              >
                Scan QR code
              </button>
              <button
                className="btn btn-secondary"
                onClick={handleChoosePhoto}
                disabled={decoding}
              >
                {decoding ? 'Reading image…' : 'Choose from photos'}
              </button>
            </div>
          </div>

          {cameraError && (
            <div
              className="card section"
              style={{
                background: 'var(--warning-light, #fff8e1)',
                borderColor: 'var(--warning, #f9a825)',
              }}
            >
              <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: 0 }}>
                {cameraError}
              </p>
            </div>
          )}

          {error && (
            <div
              className="card section"
              style={{
                background: 'var(--danger-light, #fdecea)',
                borderColor: 'var(--danger, #e53935)',
              }}
            >
              <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: 0 }}>
                {error}
              </p>
            </div>
          )}

          <div
            className="card section"
            style={{ border: '1px dashed var(--border)', background: 'none' }}
          >
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: 0 }}>
              No personal data is shared — only your age range and verification status.
            </p>
          </div>

          <div className="section">
            <button className="btn btn-ghost" onClick={onBack}>
              Back
            </button>
          </div>
        </>
      ) : (
        <>
          <div className="section" style={{ marginBottom: 8 }}>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
              Point your camera at the QR code on the website.
            </p>
          </div>

          <div className="section">
            <QRScanner onScan={handleQRData} active={scannerActive} />
          </div>

          {error && (
            <div
              className="card section"
              style={{
                background: 'var(--danger-light, #fdecea)',
                borderColor: 'var(--danger, #e53935)',
              }}
            >
              <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: 0 }}>
                {error}
              </p>
            </div>
          )}

          <div className="section">
            <button className="btn btn-ghost" onClick={handleCancelScan}>
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}
