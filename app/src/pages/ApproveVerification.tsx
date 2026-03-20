import type { VerifyRequest } from '../lib/presentation';
import type { StoredCredential } from '../types';

interface Props {
  request: VerifyRequest;
  credential: StoredCredential | null;
  onApprove: () => void;
  onDeny: () => void;
  onNavigateGetVerified?: () => void;
}

export function ApproveVerification({ request, credential, onApprove, onDeny, onNavigateGetVerified }: Props) {
  const VALID_AGE_RANGES = ['0-3', '4-7', '8-12', '13-17', '18+'];
  const safeAgeRange = VALID_AGE_RANGES.includes(request.requiredAgeRange)
    ? request.requiredAgeRange
    : 'unknown';
  const originDisplay = request.origin || 'A website';

  if (!credential) {
    return (
      <div className="fade-in" role="main">
        <div className="section">
          <h2 style={{ marginBottom: 8 }}>Age Verification Request</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
            {originDisplay} wants to verify you are {safeAgeRange}.
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
              You need to get verified first before you can prove your age to websites.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {onNavigateGetVerified && (
              <button className="btn btn-primary" onClick={onNavigateGetVerified}>
                Get Verified
              </button>
            )}
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
        <h2 style={{ marginBottom: 8 }}>Age Verification Request</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
          {originDisplay} wants to verify you are {safeAgeRange}.
        </p>
      </div>

      <div className="card section">
        <div className="section-title">What will be shared</div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {[
            { label: `Your age range (${safeAgeRange})`, shared: true },
            { label: 'Your verification tier', shared: true },
            { label: 'Your name', shared: false },
            { label: 'Your date of birth', shared: false },
            { label: 'Your document details', shared: false },
          ].map(({ label, shared }) => (
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
