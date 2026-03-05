import { useState, useCallback } from 'react';
import type { StoredIdentity } from '../lib/db';
import { generateMnemonic, validateMnemonic } from '../lib/signet';
import { WordGrid } from '../components/WordGrid';

interface OnboardingProps {
  onCreate: (role: StoredIdentity['role'], displayName: string) => Promise<void>;
  onImport: (mnemonic: string, role: StoredIdentity['role'], displayName: string) => Promise<void>;
  onImportNsec?: (nsec: string, role: StoredIdentity['role'], displayName: string) => Promise<void>;
  isAddingAccount?: boolean;
  onCancel?: () => void;
}

type Flow = 'create' | 'import' | 'nsec';
type Role = StoredIdentity['role'];

// Step numbers:
// 1 = Welcome
// 2 = Account type (create flow only)
// 3 = Show mnemonic (create) or Enter mnemonic (import)
// 4 = Verify words (create flow only)
// 5 = Set display name

export function Onboarding({ onCreate, onImport, onImportNsec, isAddingAccount, onCancel }: OnboardingProps) {
  const [step, setStep] = useState(1);
  const [flow, setFlow] = useState<Flow | null>(null);
  const [role, setRole] = useState<Role | null>(null);
  const [mnemonic, setMnemonic] = useState('');
  const [importText, setImportText] = useState('');
  const [nsecText, setNsecText] = useState('');
  const [importRole, setImportRole] = useState<Role>('adult');
  const [writtenDown, setWrittenDown] = useState(false);
  const [displayName, setDisplayName] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [guardianPubkey, setGuardianPubkey] = useState('');
  const [entityType, setEntityType] = useState<'natural_person' | 'persona'>('natural_person');

  // ── Step 1: Welcome ───────────────────────────

  const handleFlowChoice = useCallback((chosen: Flow) => {
    setFlow(chosen);
    if (chosen === 'create') {
      setStep(2);
    } else if (chosen === 'nsec') {
      setStep(3);
    } else {
      setStep(3);
    }
  }, []);

  // ── Step 2: Account Type ──────────────────────

  const handleRoleChoice = useCallback((chosen: Role, entity: 'natural_person' | 'persona') => {
    setRole(chosen);
    setEntityType(entity);
    const words = generateMnemonic();
    setMnemonic(words);
    setWrittenDown(false);
    if (chosen === 'child') {
      setStep(25); // guardian pubkey entry step
    } else {
      setStep(3);
    }
  }, []);

  // ── Step 3a: Show mnemonic ────────────────────

  const handleMnemonicContinue = useCallback(() => {
    setStep(4);
  }, []);

  // ── Step 3b: Import ───────────────────────────

  const importValid = importText.trim().split(/\s+/).length === 12
    && validateMnemonic(importText.trim());

  const handleImportContinue = useCallback(() => {
    setMnemonic(importText.trim());
    setRole(importRole);
    setStep(5);
  }, [importText, importRole]);

  // ── Step 4: Verify Words ──────────────────────

  const handleVerified = useCallback(() => {
    setStep(5);
  }, []);

  const handleFailed = useCallback(() => {
    // Go back to display words
    setWrittenDown(false);
    setStep(3);
  }, []);

  // ── Step 5: Set profile ───────────────────────

  const handleComplete = useCallback(async () => {
    if (!role || !displayName.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      if (flow === 'create') {
        await onCreate(role, displayName.trim());
      } else if (flow === 'nsec') {
        await onImportNsec?.(nsecText.trim(), role, displayName.trim());
      } else {
        await onImport(mnemonic, role, displayName.trim());
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
      setSubmitting(false);
    }
  }, [role, displayName, flow, mnemonic, nsecText, onCreate, onImport, onImportNsec]);

  // ── Back handler ──────────────────────────────

  const handleBack = useCallback(() => {
    if (step === 5 && flow === 'create') {
      setStep(4);
    } else if (step === 5 && (flow === 'import' || flow === 'nsec')) {
      setStep(3);
    } else if (step === 4) {
      setWrittenDown(false);
      setStep(3);
    } else if (step === 3 && flow === 'create' && role === 'child') {
      setStep(25);
    } else if (step === 3 && flow === 'create') {
      setStep(2);
    } else if (step === 3 && (flow === 'import' || flow === 'nsec')) {
      setStep(1);
    } else if (step === 25) {
      setStep(2);
    } else if (step === 2) {
      setStep(1);
    }
  }, [step, flow, role]);

  // ── Render ────────────────────────────────────

  const containerStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    minHeight: '100dvh',
    padding: 24,
    maxWidth: 480,
    margin: '0 auto',
    width: '100%',
  };

  const headerStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 24,
    minHeight: 44,
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

  // ── STEP 1: Welcome ──

  if (step === 1) {
    return (
      <div style={{ ...containerStyle, justifyContent: 'center', alignItems: 'center', gap: 16 }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <h1
            style={{
              fontSize: 48,
              fontWeight: 700,
              color: 'var(--accent)',
              letterSpacing: -1,
              marginBottom: 8,
            }}
          >
            Signet
          </h1>
          <p
            style={{
              fontSize: 18,
              color: 'var(--text-secondary)',
              fontWeight: 400,
            }}
          >
            Your identity. Your proof.
          </p>
        </div>

        <button
          className="btn btn-primary"
          style={{ maxWidth: 320 }}
          onClick={() => handleFlowChoice('create')}
        >
          Create Identity
        </button>

        <button
          className="btn btn-secondary"
          style={{ maxWidth: 320 }}
          onClick={() => handleFlowChoice('import')}
        >
          Import via Mnemonic
        </button>

        {onImportNsec && (
          <button
            className="btn btn-secondary"
            style={{ maxWidth: 320 }}
            onClick={() => handleFlowChoice('nsec')}
          >
            Import via nsec
          </button>
        )}

        {isAddingAccount && onCancel && (
          <button
            className="btn btn-secondary"
            style={{ maxWidth: 320, marginTop: 8, opacity: 0.7 }}
            onClick={onCancel}
          >
            Cancel
          </button>
        )}
      </div>
    );
  }

  // ── STEP 2: Account Type ──

  if (step === 2) {
    const roles: { key: Role; label: string; desc: string; emoji: string; entity: 'natural_person' | 'persona' }[] = [
      {
        key: 'adult',
        label: 'Adult (Person)',
        desc: 'A Natural Person account for adults. Get verified via the two-credential ceremony to receive both a real identity and an anonymous alias.',
        emoji: '\u{1F464}',
        entity: 'natural_person',
      },
      {
        key: 'child',
        label: 'Child',
        desc: 'An account for a child, linked to a verified parent or guardian. Requires guardian pubkey.',
        emoji: '\u{1F9D2}',
        entity: 'natural_person',
      },
      {
        key: 'verifier',
        label: 'Verifier',
        desc: 'A professional verification account for notaries, lawyers, or other trusted parties.',
        emoji: '\u{1F6E1}\uFE0F',
        entity: 'natural_person',
      },
      {
        key: 'adult',
        label: 'Alias (Persona)',
        desc: 'A standalone anonymous alias. Tier 1 (self-declared). Can be linked to a verified identity later via identity bridge.',
        emoji: '\u{1F3AD}',
        entity: 'persona',
      },
    ];

    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <button style={backBtnStyle} onClick={handleBack} aria-label="Back">
            &#8592;
          </button>
        </div>

        <h2
          style={{
            fontSize: 24,
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: 8,
          }}
        >
          Who is this account for?
        </h2>
        <p
          style={{
            fontSize: 14,
            color: 'var(--text-secondary)',
            marginBottom: 24,
          }}
        >
          Choose the type that best describes how you will use Signet.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {roles.map((r, i) => (
            <button
              key={`${r.key}-${r.entity}`}
              onClick={() => handleRoleChoice(r.key, r.entity)}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 14,
                background: 'var(--bg-card)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
                padding: 20,
                cursor: 'pointer',
                textAlign: 'left',
                boxShadow: 'var(--shadow)',
                transition: 'border-color 0.15s, box-shadow 0.15s',
                minHeight: 44,
                WebkitTapHighlightColor: 'transparent',
              }}
            >
              <span style={{ fontSize: 28, lineHeight: 1, flexShrink: 0 }}>{r.emoji}</span>
              <div>
                <div
                  style={{
                    fontSize: 16,
                    fontWeight: 600,
                    color: 'var(--text-primary)',
                    marginBottom: 4,
                  }}
                >
                  {r.label}
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {r.desc}
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>
    );
  }

  // ── STEP 2.5: Guardian Pubkey (child flow) ──

  if (step === 25) {
    const pubkeyValid = guardianPubkey.trim().length === 64 && /^[0-9a-f]+$/.test(guardianPubkey.trim());

    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <button style={backBtnStyle} onClick={() => setStep(2)} aria-label="Back">
            &#8592;
          </button>
        </div>

        <h2
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: 8,
          }}
        >
          Guardian Link
        </h2>
        <p
          style={{
            fontSize: 14,
            color: 'var(--text-secondary)',
            marginBottom: 20,
            lineHeight: 1.5,
          }}
        >
          Enter your parent or guardian&apos;s public key (hex format). They must have a Tier 3+ verified account.
        </p>

        <input
          className="input"
          type="text"
          value={guardianPubkey}
          onChange={(e) => setGuardianPubkey(e.target.value.toLowerCase())}
          placeholder="Guardian's public key (64 hex characters)"
          style={{
            fontFamily: 'monospace',
            fontSize: 13,
          }}
        />

        <div
          style={{
            marginTop: 8,
            fontSize: 13,
            color: guardianPubkey.trim().length === 0
              ? 'var(--text-muted)'
              : pubkeyValid
                ? 'var(--success)'
                : 'var(--danger)',
          }}
        >
          {guardianPubkey.trim().length === 0
            ? 'Paste or scan guardian pubkey'
            : pubkeyValid
              ? '\u2713 Valid public key format'
              : '\u2717 Must be 64 hex characters'}
        </div>

        <p
          style={{
            marginTop: 20,
            fontSize: 13,
            color: 'var(--text-secondary)',
            lineHeight: 1.5,
            padding: '12px 16px',
            background: 'var(--bg-input)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border)',
          }}
        >
          Your parent must take you to a verified professional to complete your identity verification. The professional will issue your credentials with a guardian link.
        </p>

        <button
          className="btn btn-primary"
          style={{ marginTop: 24 }}
          disabled={!pubkeyValid}
          onClick={() => setStep(3)}
        >
          Continue
        </button>
      </div>
    );
  }

  // ── STEP 3a: Show Mnemonic (create) ──

  if (step === 3 && flow === 'create') {
    const wordList = mnemonic.split(' ');

    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <button style={backBtnStyle} onClick={handleBack} aria-label="Back">
            &#8592;
          </button>
        </div>

        <h2
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: 8,
          }}
        >
          Your Recovery Phrase
        </h2>
        <p
          style={{
            fontSize: 14,
            color: 'var(--text-secondary)',
            marginBottom: 20,
            lineHeight: 1.5,
          }}
        >
          Write down these 12 words in order. They are the only way to recover your identity.
          Never share them with anyone.
        </p>

        <WordGrid words={wordList} mode="display" />

        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            marginTop: 24,
            cursor: 'pointer',
            minHeight: 44,
            WebkitTapHighlightColor: 'transparent',
          }}
        >
          <input
            type="checkbox"
            checked={writtenDown}
            onChange={(e) => setWrittenDown(e.target.checked)}
            style={{ width: 20, height: 20, accentColor: 'var(--accent)', flexShrink: 0 }}
          />
          <span style={{ fontSize: 14, color: 'var(--text-primary)' }}>
            I have written down these words in a safe place
          </span>
        </label>

        <button
          className="btn btn-primary"
          style={{ marginTop: 16 }}
          disabled={!writtenDown}
          onClick={handleMnemonicContinue}
        >
          Continue
        </button>
      </div>
    );
  }

  // ── STEP 3b: Import Mnemonic ──

  if (step === 3 && flow === 'import') {
    const wordCount = importText.trim() ? importText.trim().split(/\s+/).length : 0;

    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <button style={backBtnStyle} onClick={handleBack} aria-label="Back">
            &#8592;
          </button>
        </div>

        <h2
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: 8,
          }}
        >
          Import Your Identity
        </h2>
        <p
          style={{
            fontSize: 14,
            color: 'var(--text-secondary)',
            marginBottom: 20,
            lineHeight: 1.5,
          }}
        >
          Enter your 12-word recovery phrase, separated by spaces.
        </p>

        <textarea
          className="input"
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
          placeholder="word1 word2 word3 ..."
          rows={4}
          style={{
            resize: 'none',
            fontFamily: 'monospace',
            fontSize: 14,
            lineHeight: 1.6,
          }}
        />

        <div
          style={{
            marginTop: 8,
            fontSize: 13,
            color: wordCount === 0
              ? 'var(--text-muted)'
              : importValid
                ? 'var(--success)'
                : 'var(--danger)',
          }}
        >
          {wordCount === 0
            ? 'Enter 12 words'
            : importValid
              ? '\u2713 Valid recovery phrase'
              : wordCount !== 12
                ? `${wordCount}/12 words entered`
                : '\u2717 Invalid recovery phrase'}
        </div>

        {/* Account type selector for import */}
        <div style={{ marginTop: 24 }}>
          <p
            style={{
              fontSize: 14,
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginBottom: 10,
            }}
          >
            Account type
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            {(['adult', 'child', 'verifier'] as Role[]).map((r) => (
              <button
                key={r}
                onClick={() => setImportRole(r)}
                style={{
                  flex: 1,
                  padding: '10px 8px',
                  borderRadius: 'var(--radius-sm)',
                  border: `2px solid ${importRole === r ? 'var(--accent)' : 'var(--border)'}`,
                  background: importRole === r ? 'var(--accent)' : 'var(--bg-input)',
                  color: importRole === r ? 'var(--accent-text)' : 'var(--text-primary)',
                  fontSize: 14,
                  fontWeight: 600,
                  cursor: 'pointer',
                  minHeight: 44,
                  textTransform: 'capitalize',
                  transition: 'background 0.15s, border-color 0.15s, color 0.15s',
                  WebkitTapHighlightColor: 'transparent',
                }}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        <button
          className="btn btn-primary"
          style={{ marginTop: 24 }}
          disabled={!importValid}
          onClick={handleImportContinue}
        >
          Continue
        </button>
      </div>
    );
  }

  // ── STEP 3c: Import via nsec ──

  if (step === 3 && flow === 'nsec') {
    const nsecValid = nsecText.trim().startsWith('nsec1') && nsecText.trim().length > 50;

    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <button style={backBtnStyle} onClick={handleBack} aria-label="Back">
            &#8592;
          </button>
        </div>

        <h2
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: 8,
          }}
        >
          Import via nsec
        </h2>
        <p
          style={{
            fontSize: 14,
            color: 'var(--text-secondary)',
            marginBottom: 20,
            lineHeight: 1.5,
          }}
        >
          Paste your Nostr private key (nsec format). Note: nsec-imported accounts cannot use Shamir backup.
        </p>

        <input
          className="input"
          type="password"
          value={nsecText}
          onChange={(e) => setNsecText(e.target.value)}
          placeholder="nsec1..."
          autoFocus
          style={{
            fontFamily: 'monospace',
            fontSize: 14,
          }}
        />

        <div
          style={{
            marginTop: 8,
            fontSize: 13,
            color: nsecText.trim().length === 0
              ? 'var(--text-muted)'
              : nsecValid
                ? 'var(--success)'
                : 'var(--danger)',
          }}
        >
          {nsecText.trim().length === 0
            ? 'Enter your nsec key'
            : nsecValid
              ? '\u2713 Valid nsec format'
              : '\u2717 Must start with nsec1'}
        </div>

        {/* Account type selector */}
        <div style={{ marginTop: 24 }}>
          <p
            style={{
              fontSize: 14,
              fontWeight: 600,
              color: 'var(--text-primary)',
              marginBottom: 10,
            }}
          >
            Account type
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            {(['adult', 'child', 'verifier'] as Role[]).map((r) => (
              <button
                key={r}
                onClick={() => { setImportRole(r); setRole(r); }}
                style={{
                  flex: 1,
                  padding: '10px 8px',
                  borderRadius: 'var(--radius-sm)',
                  border: `2px solid ${importRole === r ? 'var(--accent)' : 'var(--border)'}`,
                  background: importRole === r ? 'var(--accent)' : 'var(--bg-input)',
                  color: importRole === r ? 'var(--accent-text)' : 'var(--text-primary)',
                  fontSize: 14,
                  fontWeight: 600,
                  cursor: 'pointer',
                  minHeight: 44,
                  textTransform: 'capitalize',
                  transition: 'background 0.15s, border-color 0.15s, color 0.15s',
                  WebkitTapHighlightColor: 'transparent',
                }}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        <button
          className="btn btn-primary"
          style={{ marginTop: 24 }}
          disabled={!nsecValid}
          onClick={() => { setRole(importRole); setStep(5); }}
        >
          Continue
        </button>
      </div>
    );
  }

  // ── STEP 4: Verify Words ──

  if (step === 4) {
    const wordList = mnemonic.split(' ');

    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <button style={backBtnStyle} onClick={handleBack} aria-label="Back">
            &#8592;
          </button>
        </div>

        <h2
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: 8,
          }}
        >
          Verify Your Phrase
        </h2>
        <p
          style={{
            fontSize: 14,
            color: 'var(--text-secondary)',
            marginBottom: 20,
            lineHeight: 1.5,
          }}
        >
          Confirm you wrote down your recovery phrase correctly by selecting the right words.
        </p>

        <WordGrid
          words={wordList}
          mode="verify"
          onVerified={handleVerified}
          onFailed={handleFailed}
        />
      </div>
    );
  }

  // ── STEP 5: Set Profile ──

  if (step === 5) {
    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <button style={backBtnStyle} onClick={handleBack} aria-label="Back">
            &#8592;
          </button>
        </div>

        <h2
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--text-primary)',
            marginBottom: 8,
          }}
        >
          Set Your Profile
        </h2>
        <p
          style={{
            fontSize: 14,
            color: 'var(--text-secondary)',
            marginBottom: 20,
            lineHeight: 1.5,
          }}
        >
          Choose a display name. This is how others will see you.
        </p>

        <input
          className="input"
          type="text"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder="Display name"
          maxLength={50}
          autoFocus
        />

        {error && (
          <p
            style={{
              marginTop: 12,
              fontSize: 14,
              color: 'var(--danger)',
            }}
          >
            {error}
          </p>
        )}

        <button
          className="btn btn-primary"
          style={{ marginTop: 24 }}
          disabled={!displayName.trim() || submitting}
          onClick={handleComplete}
        >
          {submitting ? 'Setting up...' : 'Complete Setup'}
        </button>
      </div>
    );
  }

  return null;
}
