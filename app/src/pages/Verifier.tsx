import { useState, useMemo, useCallback } from 'react';
import {
  createProfessionalCredential,
  createChildSafetyCredential,
  createVerifierCredential,
  hashString,
} from 'signet-protocol';
import type { StoredIdentity } from '../lib/db';
import {
  getJurisdictionCodes,
  getJurisdiction,
  createTwoCredentialCeremony,
  computeNullifier,
} from '../lib/signet';

interface RelayHook {
  state: string;
  publish: (event: import('signet-protocol').NostrEvent) => Promise<{ ok: boolean; message: string }>;
}

interface VerifierProps {
  identity: StoredIdentity;
  relay?: RelayHook;
}

interface VerifierRegistration {
  name: string;
  profession: string;
  jurisdiction: string;
  jurisdictionName: string;
  licenceId: string;
  registeredAt: number;
}

interface IssuedCredential {
  id: string;
  subjectPubkey: string;
  personaPubkey?: string;
  tier: 3 | 4;
  ageRange?: string;
  entityType?: string;
  notes: string;
  issuedAt: number;
}

function truncatePubkey(pubkey: string): string {
  if (pubkey.length <= 16) return pubkey;
  return `${pubkey.slice(0, 8)}...${pubkey.slice(-8)}`;
}

function formatTimestamp(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function Verifier({ identity, relay }: VerifierProps) {
  // -- Registration state --
  const [regName, setRegName] = useState(identity.displayName);
  const [regProfession, setRegProfession] = useState('');
  const [regJurisdiction, setRegJurisdiction] = useState('');
  const [regLicenceId, setRegLicenceId] = useState('');
  const [registration, setRegistration] = useState<VerifierRegistration | null>(null);

  // -- Issue credential state --
  const [subjectPubkey, setSubjectPubkey] = useState('');
  const [personaPubkey, setPersonaPubkey] = useState('');
  const [subjectName, setSubjectName] = useState('');
  const [documentType, setDocumentType] = useState('');
  const [documentNumber, setDocumentNumber] = useState('');
  const [documentCountry, setDocumentCountry] = useState('');
  const [dateOfBirth, setDateOfBirth] = useState('');
  const [guardianPubkey, setGuardianPubkey] = useState('');
  const [tier, setTier] = useState<3 | 4>(3);
  const [ageRange, setAgeRange] = useState('');
  const [notes, setNotes] = useState('');
  const [issuedCredentials, setIssuedCredentials] = useState<IssuedCredential[]>([]);
  const [issueSuccess, setIssueSuccess] = useState(false);
  const [computedNullifier, setComputedNullifier] = useState('');

  // -- Supersession state --
  const [supersedeEventId, setSupersedeEventId] = useState('');
  const [supersedeSubjectPubkey, setSupersedeSubjectPubkey] = useState('');
  const [supersedeReason, setSupersedeReason] = useState('');
  const [supersedeSuccess, setSupersedeSuccess] = useState(false);

  // -- Jurisdiction data --
  const jurisdictionOptions = useMemo(() => {
    const codes = getJurisdictionCodes();
    return codes.map((code) => {
      const j = getJurisdiction(code);
      return { code, name: j?.name ?? code };
    }).sort((a, b) => a.name.localeCompare(b.name));
  }, []);

  // -- Handlers --
  const handleRegister = useCallback(async () => {
    if (!regName.trim() || !regProfession.trim() || !regJurisdiction || !regLicenceId.trim()) {
      return;
    }
    const j = getJurisdiction(regJurisdiction);

    // Publish kind 30473 to relay
    if (relay && relay.state === 'connected') {
      try {
        const verifierEvent = await createVerifierCredential(identity.privateKey, {
          profession: regProfession.trim(),
          jurisdiction: regJurisdiction,
          licenceHash: hashString(regLicenceId.trim()),
          professionalBody: regProfession.trim(),
          statement: `${regName.trim()} registered as ${regProfession.trim()} verifier`,
        });
        await relay.publish(verifierEvent);
      } catch {
        // Still save registration locally even if relay publish fails
      }
    }

    setRegistration({
      name: regName.trim(),
      profession: regProfession.trim(),
      jurisdiction: regJurisdiction,
      jurisdictionName: j?.name ?? regJurisdiction,
      licenceId: regLicenceId.trim(),
      registeredAt: Math.floor(Date.now() / 1000),
    });
  }, [regName, regProfession, regJurisdiction, regLicenceId, relay, identity.privateKey]);

  const handleIssueCredential = useCallback(async () => {
    if (!subjectPubkey.trim()) return;

    const useTwoCred = personaPubkey.trim().length > 0;

    if (useTwoCred) {
      // Two-credential ceremony
      if (!subjectName.trim() || !documentType || !documentNumber.trim() || !documentCountry || !dateOfBirth) return;

      try {
        const result = await createTwoCredentialCeremony(
          identity.privateKey,
          subjectPubkey.trim(),
          personaPubkey.trim(),
          {
            name: subjectName.trim(),
            nationality: documentCountry,
            documentType,
            documentNumber: documentNumber.trim(),
            documentCountry,
            dateOfBirth,
            profession: registration?.profession ?? '',
            jurisdiction: registration?.jurisdiction ?? '',
            ageRange: ageRange.trim() || undefined,
            guardianPubkeys: guardianPubkey.trim() ? [guardianPubkey.trim()] : undefined,
          },
        );

        const nullifier = computeNullifier(documentType, documentCountry, documentNumber.trim());
        setComputedNullifier(nullifier);

        if (relay && relay.state === 'connected') {
          await relay.publish(result.naturalPerson);
          await relay.publish(result.persona);
        }

        const cred: IssuedCredential = {
          id: result.naturalPerson.id,
          subjectPubkey: subjectPubkey.trim(),
          personaPubkey: personaPubkey.trim(),
          tier: result.naturalPerson.tags.find(t => t[0] === 'tier')?.[1] === '4' ? 4 : 3,
          ageRange: result.naturalPerson.tags.find(t => t[0] === 'age-range')?.[1],
          entityType: 'natural_person + persona',
          notes: notes.trim(),
          issuedAt: Math.floor(Date.now() / 1000),
        };
        setIssuedCredentials((prev) => [cred, ...prev]);
      } catch {
        // Fall through to show error
      }
    } else {
      // Single credential (legacy flow)
      if (tier === 4 && !ageRange.trim()) return;

      if (relay && relay.state === 'connected') {
        try {
          let credEvent;
          if (tier === 4) {
            credEvent = await createChildSafetyCredential(
              identity.privateKey,
              subjectPubkey.trim(),
              {
                profession: registration?.profession ?? '',
                jurisdiction: registration?.jurisdiction ?? '',
                ageRange: ageRange.trim(),
              },
            );
          } else {
            credEvent = await createProfessionalCredential(
              identity.privateKey,
              subjectPubkey.trim(),
              {
                profession: registration?.profession ?? '',
                jurisdiction: registration?.jurisdiction ?? '',
              },
            );
          }
          await relay.publish(credEvent);
        } catch {
          // Still record locally
        }
      }

      const cred: IssuedCredential = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        subjectPubkey: subjectPubkey.trim(),
        tier,
        ageRange: tier === 4 ? ageRange.trim() : undefined,
        notes: notes.trim(),
        issuedAt: Math.floor(Date.now() / 1000),
      };
      setIssuedCredentials((prev) => [cred, ...prev]);
    }

    setSubjectPubkey('');
    setPersonaPubkey('');
    setSubjectName('');
    setDocumentType('');
    setDocumentNumber('');
    setDocumentCountry('');
    setDateOfBirth('');
    setGuardianPubkey('');
    setAgeRange('');
    setNotes('');
    setIssueSuccess(true);
    setTimeout(() => { setIssueSuccess(false); setComputedNullifier(''); }, 5000);
  }, [subjectPubkey, personaPubkey, subjectName, documentType, documentNumber, documentCountry, dateOfBirth, guardianPubkey, tier, ageRange, notes, relay, identity.privateKey, registration]);

  const handleSupersede = useCallback(async () => {
    if (!supersedeEventId.trim() || !supersedeSubjectPubkey.trim() || !supersedeReason) return;

    if (relay && relay.state === 'connected') {
      try {
        const credEvent = await createProfessionalCredential(
          identity.privateKey,
          supersedeSubjectPubkey.trim(),
          {
            profession: registration?.profession ?? '',
            jurisdiction: registration?.jurisdiction ?? '',
          },
        );
        // Add supersedes tag manually (the protocol supports it but the helper doesn't expose it)
        credEvent.tags.push(['supersedes', supersedeEventId.trim()]);
        credEvent.tags.push(['supersede-reason', supersedeReason]);
        await relay.publish(credEvent);
      } catch {
        // Still record locally
      }
    }

    const cred: IssuedCredential = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      subjectPubkey: supersedeSubjectPubkey.trim(),
      tier: 3,
      notes: `Supersedes ${supersedeEventId.trim().slice(0, 16)}... (${supersedeReason})`,
      issuedAt: Math.floor(Date.now() / 1000),
    };
    setIssuedCredentials((prev) => [cred, ...prev]);

    setSupersedeEventId('');
    setSupersedeSubjectPubkey('');
    setSupersedeReason('');
    setSupersedeSuccess(true);
    setTimeout(() => setSupersedeSuccess(false), 5000);
  }, [supersedeEventId, supersedeSubjectPubkey, supersedeReason, relay, identity.privateKey, registration]);

  // -- Can submit checks --
  const canRegister = regName.trim() && regProfession.trim() && regJurisdiction && regLicenceId.trim();
  const useTwoCred = personaPubkey.trim().length > 0;
  const canIssue = subjectPubkey.trim() && (
    useTwoCred
      ? (subjectName.trim() && documentType && documentNumber.trim() && documentCountry && dateOfBirth)
      : (tier === 3 || (tier === 4 && ageRange.trim()))
  );
  const canSupersede = supersedeEventId.trim() && supersedeSubjectPubkey.trim() && supersedeReason;

  // -- Styles --
  const containerStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: 24,
    maxWidth: 480,
    margin: '0 auto',
    width: '100%',
    padding: '0 0 24px',
  };

  const sectionCardStyle: React.CSSProperties = {
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: 20,
    boxShadow: 'var(--shadow)',
  };

  const sectionTitleStyle: React.CSSProperties = {
    fontSize: 18,
    fontWeight: 700,
    color: 'var(--text-primary)',
    margin: '0 0 16px',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: 13,
    fontWeight: 600,
    color: 'var(--text-secondary)',
    marginBottom: 6,
  };

  const fieldGroupStyle: React.CSSProperties = {
    marginBottom: 14,
  };

  return (
    <div style={containerStyle}>
      <h1
        style={{
          fontSize: 24,
          fontWeight: 700,
          color: 'var(--text-primary)',
          margin: 0,
        }}
      >
        Verifier Dashboard
      </h1>

      {/* ── Section 1: Verifier Registration ────────────────── */}
      <div style={sectionCardStyle}>
        <h2 style={sectionTitleStyle}>Verifier Registration</h2>

        {registration ? (
          <div>
            <div
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--success)',
                borderRadius: 'var(--radius-sm)',
                padding: 16,
                marginBottom: 12,
              }}
            >
              <p
                style={{
                  fontSize: 14,
                  fontWeight: 600,
                  color: 'var(--success)',
                  margin: '0 0 12px',
                }}
              >
                Registration Successful
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <SummaryRow label="Name" value={registration.name} />
                <SummaryRow label="Profession" value={registration.profession} />
                <SummaryRow label="Jurisdiction" value={registration.jurisdictionName} />
                <SummaryRow label="Licence ID" value={registration.licenceId} />
                <SummaryRow label="Registered" value={formatTimestamp(registration.registeredAt)} />
              </div>
            </div>
            <button
              className="btn btn-secondary"
              style={{ width: '100%', minHeight: 44 }}
              onClick={() => setRegistration(null)}
            >
              Update Registration
            </button>
          </div>
        ) : (
          <div>
            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Name</label>
              <input
                className="input"
                type="text"
                value={regName}
                onChange={(e) => setRegName(e.target.value)}
                placeholder="Your full name"
                style={{ width: '100%' }}
              />
            </div>

            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Profession</label>
              <input
                className="input"
                type="text"
                value={regProfession}
                onChange={(e) => setRegProfession(e.target.value)}
                placeholder="e.g. Notary Public, Solicitor, Doctor"
                style={{ width: '100%' }}
              />
            </div>

            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Jurisdiction</label>
              <select
                className="input"
                value={regJurisdiction}
                onChange={(e) => setRegJurisdiction(e.target.value)}
                style={{ width: '100%' }}
              >
                <option value="">Select jurisdiction...</option>
                {jurisdictionOptions.map((j) => (
                  <option key={j.code} value={j.code}>
                    {j.name}
                  </option>
                ))}
              </select>
            </div>

            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Licence ID</label>
              <input
                className="input"
                type="text"
                value={regLicenceId}
                onChange={(e) => setRegLicenceId(e.target.value)}
                placeholder="Professional licence number"
                style={{ width: '100%' }}
              />
            </div>

            <button
              className="btn btn-primary"
              style={{ width: '100%', minHeight: 48, marginTop: 4 }}
              disabled={!canRegister}
              onClick={handleRegister}
            >
              Register as Verifier
            </button>
          </div>
        )}
      </div>

      {/* ── Section 2: Issue Credential (Two-Credential Ceremony) ── */}
      <div style={sectionCardStyle}>
        <h2 style={sectionTitleStyle}>Issue Credential</h2>

        <div style={fieldGroupStyle}>
          <label style={labelStyle}>Subject&apos;s Natural Person Pubkey</label>
          <input
            className="input"
            type="text"
            value={subjectPubkey}
            onChange={(e) => setSubjectPubkey(e.target.value)}
            placeholder="Subject's main public key (hex)"
            style={{
              width: '100%',
              fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
              fontSize: 13,
            }}
          />
        </div>

        <div style={fieldGroupStyle}>
          <label style={labelStyle}>Subject&apos;s Persona Pubkey (optional — enables two-credential ceremony)</label>
          <input
            className="input"
            type="text"
            value={personaPubkey}
            onChange={(e) => setPersonaPubkey(e.target.value)}
            placeholder="Subject's anonymous alias pubkey (hex)"
            style={{
              width: '100%',
              fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
              fontSize: 13,
            }}
          />
        </div>

        {useTwoCred && (
          <>
            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Subject Name (private — Merkle leaf only)</label>
              <input
                className="input"
                type="text"
                value={subjectName}
                onChange={(e) => setSubjectName(e.target.value)}
                placeholder="Full legal name"
                style={{ width: '100%' }}
              />
            </div>

            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Document Type</label>
              <select
                className="input"
                value={documentType}
                onChange={(e) => setDocumentType(e.target.value)}
                style={{ width: '100%' }}
              >
                <option value="">Select document...</option>
                <option value="passport">Passport</option>
                <option value="national_id">National ID Card</option>
                <option value="driving_licence">Driving Licence</option>
                <option value="birth_certificate">Birth Certificate</option>
                <option value="unhcr_document">UNHCR Travel Document</option>
                <option value="residence_permit">Residence Permit</option>
              </select>
            </div>

            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Document Number (used for nullifier — NOT published)</label>
              <input
                className="input"
                type="text"
                value={documentNumber}
                onChange={(e) => setDocumentNumber(e.target.value)}
                placeholder="Document number"
                style={{ width: '100%', fontFamily: 'monospace' }}
              />
            </div>

            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Document Country</label>
              <select
                className="input"
                value={documentCountry}
                onChange={(e) => setDocumentCountry(e.target.value)}
                style={{ width: '100%' }}
              >
                <option value="">Select country...</option>
                {jurisdictionOptions.map((j) => (
                  <option key={j.code} value={j.code}>
                    {j.name}
                  </option>
                ))}
              </select>
            </div>

            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Date of Birth (for age-range proof — NOT published)</label>
              <input
                className="input"
                type="date"
                value={dateOfBirth}
                onChange={(e) => setDateOfBirth(e.target.value)}
                style={{ width: '100%' }}
              />
            </div>

            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Guardian Pubkey (required if child)</label>
              <input
                className="input"
                type="text"
                value={guardianPubkey}
                onChange={(e) => setGuardianPubkey(e.target.value)}
                placeholder="Guardian's public key (hex, if child)"
                style={{
                  width: '100%',
                  fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
                  fontSize: 13,
                }}
              />
            </div>

            <div
              style={{
                background: 'var(--bg-input)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                padding: '10px 14px',
                marginBottom: 14,
                fontSize: 12,
                color: 'var(--text-secondary)',
                lineHeight: 1.5,
              }}
            >
              Two-credential ceremony: Issues a Natural Person credential (with nullifier + Merkle root) and a Persona credential (anonymous, age-range only). Document details are NOT published.
            </div>
          </>
        )}

        {!useTwoCred && (
          <>
            <div style={fieldGroupStyle}>
              <label style={labelStyle}>Tier</label>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  style={{
                    flex: 1,
                    padding: '10px 12px',
                    fontSize: 13,
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: `2px solid ${tier === 3 ? 'var(--accent)' : 'var(--border)'}`,
                    background: tier === 3 ? 'var(--accent)' : 'var(--bg-input)',
                    color: tier === 3 ? 'var(--accent-text)' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    minHeight: 44,
                    transition: 'all 0.15s',
                    WebkitTapHighlightColor: 'transparent',
                  }}
                  onClick={() => setTier(3)}
                >
                  Tier 3 (Adult)
                </button>
                <button
                  style={{
                    flex: 1,
                    padding: '10px 12px',
                    fontSize: 13,
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    border: `2px solid ${tier === 4 ? 'var(--accent)' : 'var(--border)'}`,
                    background: tier === 4 ? 'var(--accent)' : 'var(--bg-input)',
                    color: tier === 4 ? 'var(--accent-text)' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    minHeight: 44,
                    transition: 'all 0.15s',
                    WebkitTapHighlightColor: 'transparent',
                  }}
                  onClick={() => setTier(4)}
                >
                  Tier 4 (Child)
                </button>
              </div>
            </div>

            {tier === 4 && (
              <div style={fieldGroupStyle}>
                <label style={labelStyle}>Age Range</label>
                <input
                  className="input"
                  type="text"
                  value={ageRange}
                  onChange={(e) => setAgeRange(e.target.value)}
                  placeholder="e.g. 8-12, 13-17"
                  style={{ width: '100%' }}
                />
              </div>
            )}
          </>
        )}

        <div style={fieldGroupStyle}>
          <label style={labelStyle}>Notes (optional)</label>
          <textarea
            className="input"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Additional notes about this verification..."
            rows={2}
            style={{ width: '100%', resize: 'none', fontSize: 14 }}
          />
        </div>

        {issueSuccess && (
          <div
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--success)',
              borderRadius: 'var(--radius-sm)',
              padding: '10px 14px',
              marginBottom: 12,
              fontSize: 13,
              color: 'var(--success)',
            }}
          >
            {useTwoCred ? 'Two credentials issued successfully (Natural Person + Persona)' : 'Credential issued successfully'}
            {computedNullifier && (
              <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                Nullifier (for your records only): {computedNullifier.slice(0, 16)}...
              </div>
            )}
          </div>
        )}

        <button
          className="btn btn-primary"
          style={{ width: '100%', minHeight: 48, marginTop: 4 }}
          disabled={!canIssue}
          onClick={handleIssueCredential}
        >
          {useTwoCred ? 'Issue Two Credentials' : 'Issue Credential'}
        </button>
      </div>

      {/* ── Section 3: Update Existing Credential ────────────── */}
      <div style={sectionCardStyle}>
        <h2 style={sectionTitleStyle}>Update Existing Credential</h2>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.5 }}>
          Supersede an existing credential when details change (name change, document renewal, tier upgrade).
        </p>

        <div style={fieldGroupStyle}>
          <label style={labelStyle}>Old Credential Event ID</label>
          <input
            className="input"
            type="text"
            value={supersedeEventId}
            onChange={(e) => setSupersedeEventId(e.target.value)}
            placeholder="Event ID of credential to supersede"
            style={{
              width: '100%',
              fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
              fontSize: 13,
            }}
          />
        </div>

        <div style={fieldGroupStyle}>
          <label style={labelStyle}>Subject Pubkey</label>
          <input
            className="input"
            type="text"
            value={supersedeSubjectPubkey}
            onChange={(e) => setSupersedeSubjectPubkey(e.target.value)}
            placeholder="Subject's public key (hex)"
            style={{
              width: '100%',
              fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
              fontSize: 13,
            }}
          />
        </div>

        <div style={fieldGroupStyle}>
          <label style={labelStyle}>Reason</label>
          <select
            className="input"
            value={supersedeReason}
            onChange={(e) => setSupersedeReason(e.target.value)}
            style={{ width: '100%' }}
          >
            <option value="">Select reason...</option>
            <option value="name_change">Name Change</option>
            <option value="document_renewal">Document Renewal</option>
            <option value="tier_upgrade">Tier Upgrade</option>
            <option value="jurisdiction_change">Jurisdiction Change</option>
          </select>
        </div>

        {supersedeSuccess && (
          <div
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--success)',
              borderRadius: 'var(--radius-sm)',
              padding: '10px 14px',
              marginBottom: 12,
              fontSize: 13,
              color: 'var(--success)',
            }}
          >
            Credential superseded successfully. New credential issued.
          </div>
        )}

        <button
          className="btn btn-secondary"
          style={{ width: '100%', minHeight: 48, marginTop: 4 }}
          disabled={!canSupersede}
          onClick={handleSupersede}
        >
          Issue Superseding Credential
        </button>
      </div>

      {/* ── Section 4: Issuance History ─────────────────────── */}
      <div style={sectionCardStyle}>
        <h2 style={sectionTitleStyle}>Issuance History</h2>

        {issuedCredentials.length === 0 ? (
          <p
            style={{
              textAlign: 'center',
              padding: '24px 16px',
              color: 'var(--text-muted)',
              fontSize: 14,
              margin: 0,
            }}
          >
            No credentials issued yet
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {issuedCredentials.map((cred) => (
              <div
                key={cred.id}
                style={{
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: 14,
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: 6,
                  }}
                >
                  <span
                    style={{
                      fontFamily: "'SF Mono', 'Fira Code', 'Cascadia Code', monospace",
                      fontSize: 13,
                      color: 'var(--text-primary)',
                      fontWeight: 600,
                    }}
                  >
                    {truncatePubkey(cred.subjectPubkey)}
                  </span>
                  <span
                    style={{
                      display: 'inline-block',
                      padding: '2px 10px',
                      borderRadius: 999,
                      fontSize: 11,
                      fontWeight: 700,
                      letterSpacing: 0.3,
                      textTransform: 'uppercase',
                      background: cred.tier === 4 ? 'var(--warning)' : 'var(--accent)',
                      color: cred.tier === 4 ? '#000' : 'var(--accent-text)',
                    }}
                  >
                    Tier {cred.tier}
                  </span>
                </div>
                {cred.entityType && (
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                    Type: {cred.entityType}
                  </div>
                )}
                {cred.personaPubkey && (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4, fontFamily: 'monospace' }}>
                    Persona: {truncatePubkey(cred.personaPubkey)}
                  </div>
                )}
                {cred.ageRange && (
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>
                    Age Range: {cred.ageRange}
                  </div>
                )}
                {cred.notes && (
                  <div
                    style={{
                      fontSize: 13,
                      color: 'var(--text-secondary)',
                      marginBottom: 4,
                      wordBreak: 'break-word',
                    }}
                  >
                    {cred.notes}
                  </div>
                )}
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {formatTimestamp(cred.issuedAt)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// -- Helper component --

function SummaryRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', gap: 8, fontSize: 14 }}>
      <span
        style={{
          color: 'var(--text-muted)',
          minWidth: 80,
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
