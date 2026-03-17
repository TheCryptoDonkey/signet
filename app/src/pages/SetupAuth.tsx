import { useState, useEffect } from 'react';
import { isBiometricAvailable, setupBiometric, setupPIN } from '../lib/auth';

interface Props {
  encryptionKey: string;
  onComplete: () => void;
}

type Step = 'intro' | 'choose' | 'biometric-pending' | 'pin-entry' | 'pin-confirm' | 'done';

export function SetupAuth({ encryptionKey, onComplete }: Props) {
  const [step, setStep] = useState<Step>('intro');
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [pinPhase, setPinPhase] = useState<'entry' | 'confirm'>('entry');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    void isBiometricAvailable().then(setBiometricAvailable);
  }, []);

  useEffect(() => {
    if (step !== 'biometric-pending') return;
    const styleEl = document.createElement('style');
    styleEl.id = 'signet-spin-keyframe';
    styleEl.textContent = '@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
    document.head.appendChild(styleEl);
    return () => { styleEl.remove(); };
  }, [step]);

  async function handleBiometricSetup() {
    setStep('biometric-pending');
    setLoading(true);
    setError('');
    try {
      const ok = await setupBiometric(encryptionKey);
      if (ok) {
        setStep('done');
      } else {
        setError('Biometric setup failed. Please use a PIN instead.');
        setStep('choose');
      }
    } catch {
      setError('Biometric setup failed. Please use a PIN instead.');
      setStep('choose');
    } finally {
      setLoading(false);
    }
  }

  async function handlePINConfirm(confirmedPin: string) {
    if (confirmedPin !== pin) {
      setError("PINs don't match. Start again.");
      setPin('');
      setConfirmPin('');
      setPinPhase('entry');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await setupPIN(pin, encryptionKey);
      setStep('done');
    } catch {
      setError('Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  function handlePinDigit(digit: string) {
    if (pinPhase === 'entry') {
      if (pin.length >= 6) return;
      const next = pin + digit;
      setPin(next);
      if (next.length === 6) {
        // Move to confirm phase automatically
        setPinPhase('confirm');
      }
    } else {
      if (confirmPin.length >= 6) return;
      const next = confirmPin + digit;
      setConfirmPin(next);
      if (next.length === 6) {
        void handlePINConfirm(next);
      }
    }
  }

  function handlePinDelete() {
    setError('');
    if (pinPhase === 'confirm') {
      setConfirmPin(p => p.slice(0, -1));
    } else {
      setPin(p => p.slice(0, -1));
    }
  }

  function handleChoosePIN() {
    setPinPhase('entry');
    setPin('');
    setConfirmPin('');
    setError('');
    setStep('pin-entry');
  }

  const keypadRows = [
    ['1', '2', '3'],
    ['4', '5', '6'],
    ['7', '8', '9'],
    ['', '0', 'del'],
  ];

  const currentPinValue = pinPhase === 'entry' ? pin : confirmPin;

  // --- Intro ---
  if (step === 'intro') {
    return (
      <div style={fullScreenStyle}>
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div style={{ fontSize: 56, marginBottom: 16, lineHeight: 1 }}>🔐</div>
          <h1 style={{ marginBottom: 12 }}>Protect your Signet</h1>
          <p style={{ color: 'var(--text-secondary)', maxWidth: 300, margin: '0 auto' }}>
            Your private keys never leave this device unencrypted. Set up a lock so only you can access your identity.
          </p>
        </div>
        <div style={{ width: '100%', maxWidth: 320, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <button
            className="btn btn-primary"
            style={{ width: '100%' }}
            onClick={() => setStep('choose')}
          >
            Set up now
          </button>
        </div>
      </div>
    );
  }

  // --- Choose method ---
  if (step === 'choose') {
    return (
      <div style={fullScreenStyle}>
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div style={{ fontSize: 56, marginBottom: 16, lineHeight: 1 }}>🔒</div>
          <h1 style={{ marginBottom: 12 }}>How do you want to unlock?</h1>
          <p style={{ color: 'var(--text-secondary)' }}>
            Choose how to protect your Signet identity.
          </p>
        </div>
        {error && (
          <div style={{ ...errorStyle, maxWidth: 320, marginBottom: 16 }}>
            {error}
          </div>
        )}
        <div style={{ width: '100%', maxWidth: 320, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {biometricAvailable && (
            <button
              className="btn btn-primary"
              style={{ width: '100%' }}
              onClick={() => void handleBiometricSetup()}
              disabled={loading}
            >
              Use fingerprint or face
            </button>
          )}
          <button
            className={biometricAvailable ? 'btn btn-secondary' : 'btn btn-primary'}
            style={{ width: '100%' }}
            onClick={handleChoosePIN}
            disabled={loading}
          >
            Use a 6-digit PIN
          </button>
        </div>
      </div>
    );
  }

  // --- Biometric in progress ---
  if (step === 'biometric-pending') {
    return (
      <div style={fullScreenStyle}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 24 }}>
          <div style={{ width: 40, height: 40, border: '3px solid var(--border)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
        </div>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 56, marginBottom: 16, lineHeight: 1 }}>👆</div>
          <h1 style={{ marginBottom: 12 }}>Set up biometrics</h1>
          <p style={{ color: 'var(--text-secondary)' }}>
            Follow the prompt from your device to register your fingerprint or face.
          </p>
        </div>
      </div>
    );
  }

  // --- PIN entry / confirm ---
  if (step === 'pin-entry') {
    const isConfirming = pinPhase === 'confirm';
    return (
      <div style={fullScreenStyle}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontSize: 56, marginBottom: 16, lineHeight: 1 }}>🔢</div>
          <h1 style={{ marginBottom: 8 }}>
            {isConfirming ? 'Confirm your PIN' : 'Choose a 6-digit PIN'}
          </h1>
          <p style={{ color: 'var(--text-secondary)' }}>
            {isConfirming
              ? 'Enter the same PIN again to confirm'
              : 'You will use this to unlock your Signet'}
          </p>
        </div>

        {/* PIN dots */}
        <div style={{ display: 'flex', gap: 16, marginBottom: 24 }}>
          {Array.from({ length: 6 }, (_, i) => (
            <div
              key={i}
              style={{
                width: 14,
                height: 14,
                borderRadius: '50%',
                background: i < currentPinValue.length ? 'var(--accent)' : 'var(--border)',
                transition: 'background 0.15s',
              }}
            />
          ))}
        </div>

        {error && (
          <div style={{ ...errorStyle, maxWidth: 320, marginBottom: 16 }}>
            {error}
          </div>
        )}

        {/* Keypad */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, width: '100%', maxWidth: 320 }}>
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
                    style={keypadButtonStyle}
                  >
                    ⌫
                  </button>
                );
              }
              return (
                <button
                  key={`${ri}-${ki}`}
                  onClick={() => handlePinDigit(key)}
                  disabled={loading || currentPinValue.length >= 6}
                  style={{ ...keypadButtonStyle, fontSize: '1.5rem', fontWeight: 600 }}
                >
                  {key}
                </button>
              );
            })
          )}
        </div>

        {isConfirming && (
          <button
            className="btn btn-ghost"
            style={{ marginTop: 16 }}
            onClick={() => { setPinPhase('entry'); setPin(''); setConfirmPin(''); setError(''); }}
          >
            Start over
          </button>
        )}

        <button
          className="btn btn-ghost"
          style={{ marginTop: 8 }}
          onClick={() => { setStep('choose'); setPin(''); setConfirmPin(''); setError(''); }}
        >
          Back
        </button>
      </div>
    );
  }

  // --- Done ---
  if (step === 'done') {
    return (
      <div style={fullScreenStyle}>
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <div style={{ fontSize: 56, marginBottom: 16, lineHeight: 1 }}>✅</div>
          <h1 style={{ marginBottom: 12 }}>You're protected</h1>
          <p style={{ color: 'var(--text-secondary)' }}>
            Your Signet identity is now locked. Only you can unlock it.
          </p>
        </div>
        <button
          className="btn btn-primary"
          style={{ width: '100%', maxWidth: 320 }}
          onClick={onComplete}
        >
          Continue
        </button>
      </div>
    );
  }

  return null;
}

const fullScreenStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  background: 'var(--bg-primary)',
  zIndex: 1000,
  padding: '24px',
};

const errorStyle: React.CSSProperties = {
  padding: '10px 16px',
  background: 'var(--danger-light)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--danger)',
  fontSize: '0.9rem',
  textAlign: 'center',
  width: '100%',
};

const keypadButtonStyle: React.CSSProperties = {
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
};
