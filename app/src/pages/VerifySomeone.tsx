import { useState } from 'react';
import type { SignetIdentity } from '../types';
import { getActivePubkey, getActivePrivateKey, createTwoCredentialCeremony } from '../lib/signet';
import { QRCode } from '../components/QRCode';
import { QRScanner } from '../components/QRScanner';

interface Props {
  identity: SignetIdentity;
}

// Step in the ceremony flow
type Step = 'show-qr' | 'scanning' | 'review-details' | 'rejected' | 'confirmation' | 'issuing' | 'done';

interface SubjectDetails {
  fullName: string;
  dateOfBirth: string;
  nationality: string;
  documentType: string;
  documentNumber: string;
  documentCountry: string;
  documentExpiry: string;
  isChild: boolean;
  guardianPubkey?: string;
  subjectPubkey: string;
  personaPubkey: string;
}

// Shape of the QR payload from the subject's app
interface VerifyRequestPayload {
  type: string;
  naturalPersonPubkey: string;
  personaPubkey: string;
  details: {
    name: string;
    dateOfBirth: string;
    nationality: string;
    documentType: string;
    documentNumber: string;
    documentCountry: string;
    documentExpiry: string;
  };
  isChild: boolean;
  guardianPubkey: string | null;
}

function computeAgeRange(dob: string): string {
  const birthYear = new Date(dob).getFullYear();
  const currentYear = new Date().getFullYear();
  const age = currentYear - birthYear;
  if (age < 13) return '0–12';
  if (age < 18) return '13–17';
  if (age < 26) return '18–25';
  if (age < 36) return '26–35';
  if (age < 51) return '36–50';
  if (age < 66) return '51–65';
  return '66+';
}

function computeTier(details: SubjectDetails): 3 | 4 {
  return details.isChild ? 4 : 3;
}

function formatDocumentType(raw: string): string {
  return raw.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function truncatePubkey(pk: string): string {
  if (pk.length <= 16) return pk;
  return `${pk.slice(0, 8)}…${pk.slice(-8)}`;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', gap: 8, fontSize: 14, padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 120, fontWeight: 500, flexShrink: 0 }}>
        {label}
      </span>
      <span style={{ color: 'var(--text-primary)', wordBreak: 'break-word' }}>{value}</span>
    </div>
  );
}

function StepIndicator({ current, total }: { current: number; total: number }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 20 }}>
      {Array.from({ length: total }).map((_, i) => (
        <div
          key={i}
          style={{
            flex: i === current - 1 ? 2 : 1,
            height: 4,
            borderRadius: 2,
            background: i < current ? 'var(--accent, #6366f1)' : 'var(--border)',
            transition: 'flex 0.25s, background 0.25s',
          }}
        />
      ))}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function VerifySomeone({ identity }: Props) {
  const verifierPubkey = getActivePubkey(identity);
  const qrPayload = JSON.stringify({ type: 'signet-verifier-v1', pubkey: verifierPubkey });

  const [step, setStep] = useState<Step>('show-qr');
  const [subject, setSubject] = useState<SubjectDetails | null>(null);
  const [rejectNote, setRejectNote] = useState('');
  const [waitingResubmit, setWaitingResubmit] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [ceremonyError, setCeremonyError] = useState<string | null>(null);
  const [credentialQR, setCredentialQR] = useState<string | null>(null);

  // ── QR scan handler ────────────────────────────────────────────────────────

  function handleScan(data: string) {
    setScanError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      setScanError('Invalid QR code — could not parse JSON.');
      return;
    }

    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      (parsed as Record<string, unknown>).type !== 'signet-verify-request'
    ) {
      setScanError('Invalid QR code — not a Signet verify-request.');
      return;
    }

    const p = parsed as VerifyRequestPayload;

    if (
      typeof p.naturalPersonPubkey !== 'string' ||
      typeof p.personaPubkey !== 'string' ||
      typeof p.details !== 'object' ||
      p.details === null
    ) {
      setScanError('QR code is missing required fields.');
      return;
    }

    const d = p.details;
    if (
      typeof d.name !== 'string' ||
      typeof d.dateOfBirth !== 'string' ||
      typeof d.nationality !== 'string' ||
      typeof d.documentType !== 'string' ||
      typeof d.documentNumber !== 'string' ||
      typeof d.documentCountry !== 'string'
    ) {
      setScanError('QR code details are incomplete.');
      return;
    }

    const subjectDetails: SubjectDetails = {
      fullName: d.name,
      dateOfBirth: d.dateOfBirth,
      nationality: d.nationality,
      documentType: d.documentType,
      documentNumber: d.documentNumber,
      documentCountry: d.documentCountry,
      documentExpiry: typeof d.documentExpiry === 'string' ? d.documentExpiry : '',
      isChild: p.isChild === true,
      guardianPubkey: typeof p.guardianPubkey === 'string' ? p.guardianPubkey : undefined,
      subjectPubkey: p.naturalPersonPubkey,
      personaPubkey: p.personaPubkey,
    };

    setSubject(subjectDetails);
    setStep('review-details');
  }

  // ── Step navigation helpers ────────────────────────────────────────────────

  function handleConfirmDetails() {
    setStep('confirmation');
  }

  function handleRejectDetails() {
    setStep('rejected');
  }

  function handleWaitForResubmission() {
    setWaitingResubmit(true);
    // Simulate resubmission after 2 seconds for testing
    setTimeout(() => {
      setWaitingResubmit(false);
      setRejectNote('');
      setStep('scanning');
    }, 2000);
  }

  function handleCancelFromRejection() {
    setStep('show-qr');
    setSubject(null);
    setRejectNote('');
    setWaitingResubmit(false);
  }

  async function handleIssueCredentials() {
    if (!subject) return;
    setCeremonyError(null);
    setStep('issuing');

    try {
      const verifierPrivateKey = getActivePrivateKey(identity);

      const result = await createTwoCredentialCeremony(
        verifierPrivateKey,
        subject.subjectPubkey,
        subject.personaPubkey,
        {
          name: subject.fullName,
          nationality: subject.nationality,
          documentType: subject.documentType,
          documentNumber: subject.documentNumber,
          documentCountry: subject.documentCountry,
          dateOfBirth: subject.dateOfBirth,
          profession: 'professional',
          jurisdiction: 'global',
          guardianPubkeys: subject.guardianPubkey ? [subject.guardianPubkey] : undefined,
        },
      );

      const qrData = JSON.stringify({
        type: 'signet-credentials-v1',
        naturalPerson: result.naturalPerson,
        persona: result.persona,
      });

      setCredentialQR(qrData);
      setStep('done');
    } catch (err) {
      setCeremonyError(err instanceof Error ? err.message : 'Unknown error issuing credentials.');
      setStep('confirmation');
    }
  }

  function handleDone() {
    setStep('show-qr');
    setSubject(null);
    setRejectNote('');
    setWaitingResubmit(false);
    setCredentialQR(null);
    setCeremonyError(null);
  }

  function handleCancel() {
    setStep('show-qr');
    setSubject(null);
    setRejectNote('');
    setScanError(null);
    setCeremonyError(null);
    setCredentialQR(null);
  }

  // ── Step numbering (show-qr=1, scanning/review=2, rejected/confirmation=3, issuing/done=4) ──

  function stepNumber(): number {
    if (step === 'show-qr') return 1;
    if (step === 'scanning' || step === 'review-details') return 2;
    if (step === 'rejected' || step === 'confirmation') return 3;
    return 4;
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="fade-in" style={{ maxWidth: 480, margin: '0 auto', width: '100%' }}>

      <StepIndicator current={stepNumber()} total={4} />

      {/* ── Step 1: Show verifier QR ──────────────────────────────────────── */}
      {step === 'show-qr' && (
        <div>
          <div className="section">
            <h2 style={{ marginBottom: 8 }}>Your verifier code</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 24 }}>
              Show this QR code to the person you&apos;re verifying. They&apos;ll scan it with their Signet app.
            </p>

            <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 24 }}>
              <QRCode data={qrPayload} size={220} />
            </div>

            <div
              style={{
                background: 'var(--bg-input, #f5f5f5)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm, 8px)',
                padding: '10px 14px',
                fontSize: 12,
                color: 'var(--text-muted)',
                wordBreak: 'break-all',
                fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
              }}
            >
              {truncatePubkey(verifierPubkey)}
            </div>
          </div>

          <div className="section">
            <button
              className="btn btn-primary"
              style={{ width: '100%' }}
              onClick={() => { setScanError(null); setStep('scanning'); }}
            >
              They&apos;ve scanned it — scan their QR
            </button>
          </div>
        </div>
      )}

      {/* ── Step 2: Scan subject's QR code ───────────────────────────────── */}
      {step === 'scanning' && (
        <div>
          <div className="section">
            <h2 style={{ marginBottom: 8 }}>Scan their QR code</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
              Ask the person to show their Signet QR code, then scan it here.
            </p>

            <QRScanner onScan={handleScan} active={step === 'scanning'} />

            {scanError && (
              <div
                style={{
                  marginTop: 16,
                  background: 'var(--bg-input, #f5f5f5)',
                  border: '1px solid var(--danger)',
                  borderRadius: 'var(--radius-sm, 8px)',
                  padding: '10px 14px',
                  fontSize: 13,
                  color: 'var(--danger)',
                }}
              >
                {scanError}
              </div>
            )}
          </div>

          <div className="section">
            <button
              className="btn btn-ghost"
              style={{ width: '100%' }}
              onClick={handleCancel}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* ── Step 2b: Review subject's details ────────────────────────────── */}
      {step === 'review-details' && subject && (
        <div>
          <div className="section">
            <h2 style={{ marginBottom: 4 }}>Compare details to document</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
              Check each field against the physical document in front of you.
            </p>

            <div className="card" style={{ marginBottom: 20 }}>
              <DetailRow label="Full name" value={subject.fullName} />
              <DetailRow label="Date of birth" value={subject.dateOfBirth} />
              <DetailRow label="Nationality" value={subject.nationality} />
              <DetailRow label="Document type" value={formatDocumentType(subject.documentType)} />
              <DetailRow label="Document number" value={subject.documentNumber} />
              <DetailRow label="Document country" value={subject.documentCountry} />
              <DetailRow label="Expiry" value={subject.documentExpiry || '—'} />
              <DetailRow label="Person type" value={subject.isChild ? 'Child (under 18)' : 'Adult (18+)'} />
              {subject.isChild && subject.guardianPubkey && (
                <DetailRow label="Guardian pubkey" value={truncatePubkey(subject.guardianPubkey)} />
              )}
            </div>
          </div>

          <div className="section" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button
              className="btn btn-primary"
              style={{ width: '100%' }}
              onClick={handleConfirmDetails}
            >
              Confirm — details correct
            </button>
            <button
              className="btn btn-secondary"
              style={{ width: '100%', color: 'var(--danger)', borderColor: 'var(--danger)' }}
              onClick={handleRejectDetails}
            >
              Reject — details wrong
            </button>
            <button
              className="btn btn-ghost"
              style={{ width: '100%' }}
              onClick={handleCancel}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* ── Step 3a: Rejection ───────────────────────────────────────────── */}
      {step === 'rejected' && (
        <div>
          <div className="section">
            <h2 style={{ marginBottom: 4 }}>Details rejected</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
              The person can fix their details and resubmit.
            </p>

            <div
              style={{
                background: 'var(--bg-input, #f5f5f5)',
                border: '1px solid var(--danger)',
                borderRadius: 'var(--radius-sm, 8px)',
                padding: '12px 16px',
                marginBottom: 20,
                fontSize: 14,
                color: 'var(--danger)',
                fontWeight: 500,
              }}
            >
              Rejection sent to their app. Ask them to correct the details and resubmit.
            </div>

            <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
              Note for the person (optional)
            </label>
            <textarea
              className="input"
              value={rejectNote}
              onChange={e => setRejectNote(e.target.value)}
              placeholder="e.g. Name spelling doesn't match passport"
              rows={3}
              style={{ width: '100%', resize: 'none', fontSize: 14, marginBottom: 20, boxSizing: 'border-box' }}
            />
          </div>

          <div className="section" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button
              className="btn btn-primary"
              style={{ width: '100%' }}
              onClick={handleWaitForResubmission}
              disabled={waitingResubmit}
            >
              {waitingResubmit ? 'Waiting for resubmission...' : 'Wait for resubmission'}
            </button>
            <button
              className="btn btn-ghost"
              style={{ width: '100%' }}
              onClick={handleCancelFromRejection}
            >
              Cancel verification
            </button>
          </div>
        </div>
      )}

      {/* ── Step 3b: Confirmation summary ────────────────────────────────── */}
      {step === 'confirmation' && subject && (
        <div>
          <div className="section">
            <h2 style={{ marginBottom: 4 }}>Ready to issue</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 20 }}>
              Review the credentials that will be created.
            </p>

            <div className="card" style={{ marginBottom: 16 }}>
              <DetailRow label="Full name" value={subject.fullName} />
              <DetailRow label="Date of birth" value={subject.dateOfBirth} />
              <DetailRow label="Nationality" value={subject.nationality} />
              <DetailRow label="Document type" value={formatDocumentType(subject.documentType)} />
              <DetailRow label="Document number" value={subject.documentNumber} />
              <DetailRow label="Document country" value={subject.documentCountry} />
              <DetailRow label="Expiry" value={subject.documentExpiry || '—'} />
              <DetailRow label="Age range" value={computeAgeRange(subject.dateOfBirth)} />
              <DetailRow label="Tier" value={`Tier ${computeTier(subject)}`} />
              {subject.isChild && subject.guardianPubkey && (
                <DetailRow label="Guardian pubkey" value={truncatePubkey(subject.guardianPubkey)} />
              )}
            </div>

            <div
              style={{
                background: 'var(--bg-input, #f5f5f5)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm, 8px)',
                padding: '12px 16px',
                fontSize: 13,
                color: 'var(--text-secondary)',
                lineHeight: 1.6,
              }}
            >
              <strong style={{ display: 'block', marginBottom: 4, color: 'var(--text-primary)' }}>
                Two credentials will be issued:
              </strong>
              <div style={{ marginBottom: 4 }}>
                Person credential — verified identity with nullifier and Merkle root (document details are NOT published)
              </div>
              <div>
                Persona credential — anonymous, age range only ({computeAgeRange(subject.dateOfBirth)})
              </div>
            </div>

            {ceremonyError && (
              <div
                style={{
                  marginTop: 16,
                  background: 'var(--bg-input, #f5f5f5)',
                  border: '1px solid var(--danger)',
                  borderRadius: 'var(--radius-sm, 8px)',
                  padding: '10px 14px',
                  fontSize: 13,
                  color: 'var(--danger)',
                }}
              >
                Error: {ceremonyError}
              </div>
            )}
          </div>

          <div className="section" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button
              className="btn btn-primary"
              style={{ width: '100%' }}
              onClick={handleIssueCredentials}
            >
              Confirm &amp; Issue
            </button>
            <button
              className="btn btn-ghost"
              style={{ width: '100%' }}
              onClick={() => setStep('review-details')}
            >
              Back
            </button>
          </div>
        </div>
      )}

      {/* ── Step 4: Issuing (spinner) ─────────────────────────────────────── */}
      {step === 'issuing' && (
        <div>
          <div className="section">
            <h2 style={{ marginBottom: 8 }}>Issuing credentials</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 24 }}>
              Signing credentials — this will only take a moment.
            </p>

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 16,
                padding: '32px 0',
              }}
            >
              <div
                style={{
                  width: 48,
                  height: 48,
                  borderRadius: '50%',
                  border: '3px solid var(--border)',
                  borderTopColor: 'var(--accent, #6366f1)',
                  animation: 'spin 1s linear infinite',
                }}
              />
              <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                Generating credentials...
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ── Step 4: Done — show credentials QR ───────────────────────────── */}
      {step === 'done' && subject && credentialQR && (
        <div>
          <div className="section" style={{ textAlign: 'center' }}>
            <div
              style={{
                width: 64,
                height: 64,
                borderRadius: '50%',
                background: 'var(--success, #22c55e)',
                color: '#fff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 28,
                margin: '0 auto 20px',
              }}
            >
              ✓
            </div>

            <h2 style={{ marginBottom: 8 }}>Credentials Ready</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 24 }}>
              Ask {subject.fullName.split(' ')[0]} to scan this QR code to receive their credentials.
            </p>

            <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 24 }}>
              <QRCode data={credentialQR} size={240} />
            </div>

            <div className="card" style={{ textAlign: 'left', marginBottom: 0 }}>
              <DetailRow label="Issued to" value={subject.fullName} />
              <DetailRow label="Person credential" value="Ready" />
              <DetailRow label="Persona credential" value="Ready" />
              <DetailRow label="Age range" value={computeAgeRange(subject.dateOfBirth)} />
              <DetailRow label="Tier" value={`Tier ${computeTier(subject)}`} />
            </div>
          </div>

          <div className="section">
            <button
              className="btn btn-primary"
              style={{ width: '100%' }}
              onClick={handleDone}
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
