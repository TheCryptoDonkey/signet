import { useState } from 'react';

interface Props {
  identity: {
    mnemonic: string;
    backedUp?: boolean;
  };
  onMarkBackedUp: () => void;
}

type Phase = 'education' | 'backup' | 'with-verifier';

export function GetVerified({ identity, onMarkBackedUp }: Props) {
  const [phase, setPhase] = useState<Phase>('education');
  const [backedUpChecked, setBackedUpChecked] = useState(false);

  const handleEnterDetails = () => {
    if (!identity.backedUp) {
      setPhase('backup');
    } else {
      setPhase('with-verifier');
    }
  };

  const handleBackupContinue = () => {
    onMarkBackedUp();
    setPhase('with-verifier');
  };

  if (phase === 'education') {
    return (
      <div className="fade-in">
        <div className="section">
          <h2 style={{ marginBottom: 4 }}>How verification works</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
            Get your identity verified in about 3 minutes.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {[
              {
                number: 1,
                title: 'Enter your details',
                body: 'Add your name, date of birth, and document info in the app',
              },
              {
                number: 2,
                title: 'Visit a verifier',
                body: 'Your GP, solicitor, teacher, accountant, or any registered professional',
              },
              {
                number: 3,
                title: 'They check your ID',
                body: 'Show your passport or driving licence. They confirm your details on their phone.',
              },
              {
                number: 4,
                title: 'Done',
                body: 'Takes about 3 minutes.',
              },
            ].map((step, i, arr) => (
              <div
                key={step.number}
                style={{
                  display: 'flex',
                  gap: 16,
                  padding: '16px 0',
                  borderBottom: i < arr.length - 1 ? '1px solid var(--border)' : 'none',
                }}
              >
                <div
                  style={{
                    flexShrink: 0,
                    width: 32,
                    height: 32,
                    borderRadius: '50%',
                    background: 'var(--accent, #6366f1)',
                    color: '#fff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '0.9rem',
                  }}
                >
                  {step.number}
                </div>
                <div>
                  <div style={{ fontWeight: 600, marginBottom: 2 }}>{step.title}</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{step.body}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="section" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <button className="btn btn-primary" onClick={handleEnterDetails}>
            Enter my details
          </button>
          <button className="btn btn-secondary" disabled style={{ opacity: 0.5, cursor: 'not-allowed' }}>
            Find a verifier near me — Coming soon
          </button>
        </div>
      </div>
    );
  }

  if (phase === 'backup') {
    const words = identity.mnemonic.split(' ');

    return (
      <div className="fade-in">
        <div className="section">
          <h2 style={{ marginBottom: 8 }}>Before you verify</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
            You're about to tie your real identity to this account. Before you do, let's secure it properly.
          </p>

          <div className="card" style={{ marginBottom: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {words.map((word, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '4px 0' }}>
                  <span
                    style={{
                      color: 'var(--text-muted)',
                      fontSize: '0.8rem',
                      width: 20,
                      textAlign: 'right',
                      flexShrink: 0,
                    }}
                  >
                    {i + 1}
                  </span>
                  <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{word}</span>
                </div>
              ))}
            </div>
          </div>

          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              cursor: 'pointer',
              marginBottom: 20,
              fontSize: '0.9rem',
            }}
          >
            <input
              type="checkbox"
              checked={backedUpChecked}
              onChange={e => setBackedUpChecked(e.target.checked)}
              style={{ width: 18, height: 18, flexShrink: 0, cursor: 'pointer' }}
            />
            I've written these down somewhere safe
          </label>

          <button
            className="btn btn-primary"
            onClick={handleBackupContinue}
            disabled={!backedUpChecked}
            style={{ opacity: backedUpChecked ? 1 : 0.5, cursor: backedUpChecked ? 'pointer' : 'not-allowed' }}
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  // phase === 'with-verifier'
  return (
    <div className="fade-in">
      <div className="section">
        <h2 style={{ marginBottom: 8 }}>I'm with my verifier</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
          Ask them to show you their verifier QR code on their phone.
        </p>

        <button
          className="btn btn-primary"
          onClick={() => alert('Coming soon')}
          style={{ marginBottom: 16 }}
        >
          Scan verifier's QR
        </button>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          This will send your details to their app for confirmation.
        </p>
      </div>
    </div>
  );
}
