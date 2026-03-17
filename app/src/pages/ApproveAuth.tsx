import type { AuthRequest, LoginRequest } from '../lib/qr-router';
import type { StoredCredential } from '../types';

interface Props {
  request: AuthRequest | LoginRequest;
  credential: StoredCredential | null;
  onApprove: () => void;
  onDeny: () => void;
}

function isLoginRequest(r: AuthRequest | LoginRequest): r is LoginRequest {
  return r.type === 'signet-login-request';
}

function safeOrigin(origin: string): string {
  // Only display the origin — strip any path/query to avoid phishing via long strings
  try {
    const url = new URL(origin);
    return url.hostname || origin.slice(0, 64);
  } catch {
    return origin.slice(0, 64);
  }
}

const VALID_AGE_RANGES = ['0-3', '4-7', '8-12', '13-17', '18+'];

export function ApproveAuth({ request, credential, onApprove, onDeny }: Props) {
  const login = isLoginRequest(request);
  const originDisplay = safeOrigin(request.origin);
  const ageRange = login && typeof request.requiredAgeRange === 'string' && VALID_AGE_RANGES.includes(request.requiredAgeRange)
    ? request.requiredAgeRange
    : null;

  // For login+verify, require a credential that satisfies the age range
  const needsCredential = login && ageRange !== null;
  const hasCredential = credential !== null;

  type ShareItem = { label: string; shared: boolean };
  const sharedItems: ShareItem[] = [
    { label: 'Your public key', shared: true },
    ...(ageRange !== null ? [{ label: `Your age range (${ageRange})`, shared: true }] : []),
    { label: 'Your name', shared: false },
    { label: 'Your age or documents', shared: false },
  ];

  const title = login ? 'Login + Verification Request' : 'Login Request';
  const description = login
    ? `${originDisplay} wants to log you in AND verify your identity.`
    : `${originDisplay} wants to log you in with your Signet identity.`;

  if (needsCredential && !hasCredential) {
    return (
      <div className="fade-in" role="main">
        <div className="section">
          <h2 style={{ marginBottom: 8 }}>{title}</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
            {description}
          </p>

          <div
            className="card"
            style={{
              background: 'var(--warning-light, #fff8e1)',
              borderColor: 'var(--warning, #f9a825)',
              marginBottom: 20,
            }}
          >
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: 0 }}>
              This login also requires age verification ({ageRange}). You need to get verified
              before you can approve this request.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button className="btn btn-ghost" onClick={onDeny}>
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in" role="main">
      <div className="section">
        <h2 style={{ marginBottom: 8 }}>{title}</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
          {description}
        </p>
      </div>

      {login && ageRange && (
        <div className="card section" style={{ background: 'var(--warning-light, #fff8e1)', borderColor: 'var(--warning, #f9a825)' }}>
          <div style={{ fontWeight: 600, marginBottom: 4, color: 'var(--warning, #f9a825)' }}>
            This request includes identity verification
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 0 }}>
            In addition to logging you in, this website is requesting proof that you are {ageRange}. Both your public key and your age range will be shared.
          </p>
        </div>
      )}

      <div className="card section">
        <div className="section-title">What will be shared</div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {sharedItems.map(({ label, shared }) => (
            <div
              key={label}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                fontSize: '0.9rem',
              }}
            >
              <span
                style={{
                  flexShrink: 0,
                  width: 20,
                  height: 20,
                  borderRadius: '50%',
                  background: shared ? 'var(--success-light, #e8f5e9)' : 'var(--danger-light, #fdecea)',
                  border: `1px solid ${shared ? 'var(--success, #43a047)' : 'var(--danger, #e53935)'}`,
                  color: shared ? 'var(--success, #2e7d32)' : 'var(--danger, #c62828)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                }}
                aria-label={shared ? 'will be shared' : 'will not be shared'}
              >
                {shared ? '✓' : '✗'}
              </span>
              <span style={{ color: shared ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                {label}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="section" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <button className="btn btn-primary" onClick={onApprove}>
          Approve
        </button>
        <button className="btn btn-ghost" onClick={onDeny}>
          Deny
        </button>
      </div>
    </div>
  );
}
