import { useState, useEffect } from 'react';
import { authenticateBiometric, authenticatePIN, getAuthMethod } from '../lib/auth';

interface Props {
  onUnlock: (encryptionKey: string) => void;
}

export function AuthScreen({ onUnlock }: Props) {
  const method = getAuthMethod();
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPinFallback, setShowPinFallback] = useState(method === 'pin');
  const [attempts, setAttempts] = useState(() => {
    try { return parseInt(localStorage.getItem('signet-pin-attempts') || '0', 10) || 0; } catch { return 0; }
  });
  const [lockedUntil, setLockedUntil] = useState<number | null>(() => {
    try { const v = localStorage.getItem('signet-pin-locked'); return v ? parseInt(v, 10) : null; } catch { return null; }
  });

  // Persist attempts and lockedUntil to localStorage
  useEffect(() => {
    try { localStorage.setItem('signet-pin-attempts', String(attempts)); } catch { /* ignore */ }
  }, [attempts]);

  useEffect(() => {
    try {
      if (lockedUntil !== null) {
        localStorage.setItem('signet-pin-locked', String(lockedUntil));
      } else {
        localStorage.removeItem('signet-pin-locked');
      }
    } catch { /* ignore */ }
  }, [lockedUntil]);

  // Auto-trigger biometric on mount
  useEffect(() => {
    if (method === 'biometric') {
      void triggerBiometric();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function triggerBiometric() {
    setLoading(true);
    setError('');
    try {
      const key = await authenticateBiometric();
      if (key) {
        onUnlock(key);
      } else {
        setError('Biometric authentication failed. Try again or use your PIN.');
      }
    } catch {
      setError('Biometric authentication failed. Try again or use your PIN.');
    } finally {
      setLoading(false);
    }
  }

  function handlePinDigit(digit: string) {
    if (pin.length >= 6) return;
    const next = pin + digit;
    setPin(next);
    if (next.length === 6) {
      void submitPIN(next);
    }
  }

  function handlePinDelete() {
    setPin(p => p.slice(0, -1));
    setError('');
  }

  async function submitPIN(value: string) {
    // Check lockout before attempting authentication
    if (lockedUntil !== null && lockedUntil > Date.now()) {
      const secondsLeft = Math.ceil((lockedUntil - Date.now()) / 1000);
      setError(`Locked for ${secondsLeft} seconds. Please wait.`);
      setPin('');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const key = await authenticatePIN(value);
      if (key) {
        setAttempts(0);
        setLockedUntil(null);
        onUnlock(key);
      } else {
        const newAttempts = attempts + 1;
        setAttempts(newAttempts);
        if (newAttempts >= 15) {
          setLockedUntil(Date.now() + 60 * 60 * 1000); // 1 hour
          setError('Too many failed attempts. Locked for 1 hour.');
        } else if (newAttempts >= 10) {
          setLockedUntil(Date.now() + 5 * 60 * 1000); // 5 minutes
          setError('Too many failed attempts. Locked for 5 minutes.');
        } else if (newAttempts >= 5) {
          setLockedUntil(Date.now() + 30 * 1000); // 30 seconds
          setError('Too many failed attempts. Locked for 30 seconds.');
        } else {
          setError('Incorrect PIN. Please try again.');
        }
        setPin('');
      }
    } catch {
      setError('Something went wrong. Please try again.');
      setPin('');
    } finally {
      setLoading(false);
    }
  }

  const keypadRows = [
    ['1', '2', '3'],
    ['4', '5', '6'],
    ['7', '8', '9'],
    ['', '0', 'del'],
  ];

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-primary)',
      zIndex: 1000,
      padding: '24px',
    }}>
      <div style={{ textAlign: 'center', marginBottom: 40 }}>
        <div style={{ fontSize: 56, marginBottom: 16, lineHeight: 1 }}>
          {showPinFallback ? '🔢' : '🔐'}
        </div>
        <h1 style={{ marginBottom: 8 }}>
          {showPinFallback ? 'Enter your PIN' : 'Unlock Signet'}
        </h1>
        <p style={{ color: 'var(--text-secondary)' }}>
          {showPinFallback
            ? 'Enter your 6-digit PIN to continue'
            : 'Use your fingerprint or face to unlock'}
        </p>
      </div>

      {/* Biometric mode */}
      {!showPinFallback && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, width: '100%', maxWidth: 320 }}>
          {error && (
            <div style={{
              padding: '10px 16px',
              background: 'var(--danger-light)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--danger)',
              fontSize: '0.9rem',
              textAlign: 'center',
              width: '100%',
            }}>
              {error}
            </div>
          )}
          <button
            className="btn btn-primary"
            style={{ width: '100%', fontSize: '1rem', padding: '14px' }}
            onClick={() => void triggerBiometric()}
            disabled={loading}
          >
            {loading ? 'Waiting for biometric...' : 'Unlock with biometrics'}
          </button>
          <button
            className="btn btn-ghost"
            style={{ width: '100%' }}
            onClick={() => { setShowPinFallback(true); setError(''); }}
          >
            Use PIN instead
          </button>
        </div>
      )}

      {/* PIN keypad mode */}
      {showPinFallback && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 24, width: '100%', maxWidth: 320 }}>
          {/* PIN dots */}
          <div style={{ display: 'flex', gap: 16 }}>
            {Array.from({ length: 6 }, (_, i) => (
              <div
                key={i}
                style={{
                  width: 14,
                  height: 14,
                  borderRadius: '50%',
                  background: i < pin.length ? 'var(--accent)' : 'var(--border)',
                  transition: 'background 0.15s',
                }}
              />
            ))}
          </div>

          {error && (
            <div style={{
              padding: '10px 16px',
              background: 'var(--danger-light)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--danger)',
              fontSize: '0.9rem',
              textAlign: 'center',
              width: '100%',
            }}>
              {error}
            </div>
          )}

          {/* Keypad */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, width: '100%' }}>
            {keypadRows.map((row, ri) =>
              row.map((key, ki) => {
                if (key === '') {
                  return <div key={`${ri}-${ki}`} />;
                }
                if (key === 'del') {
                  return (
                    <button
                      key={`${ri}-${ki}`}
                      onClick={handlePinDelete}
                      disabled={loading}
                      style={{
                        height: 64,
                        borderRadius: 'var(--radius)',
                        border: '1px solid var(--border)',
                        background: 'var(--bg-secondary)',
                        color: 'var(--text-primary)',
                        fontSize: '1.25rem',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      ⌫
                    </button>
                  );
                }
                return (
                  <button
                    key={`${ri}-${ki}`}
                    onClick={() => handlePinDigit(key)}
                    disabled={loading || pin.length >= 6}
                    style={{
                      height: 64,
                      borderRadius: 'var(--radius)',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-secondary)',
                      color: 'var(--text-primary)',
                      fontSize: '1.5rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    {key}
                  </button>
                );
              })
            )}
          </div>

          {method === 'biometric' && (
            <button
              className="btn btn-ghost"
              style={{ width: '100%' }}
              onClick={() => { setShowPinFallback(false); setPin(''); setError(''); }}
            >
              Use biometrics instead
            </button>
          )}
        </div>
      )}
    </div>
  );
}
