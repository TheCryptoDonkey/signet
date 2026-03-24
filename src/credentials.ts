// Verification Credential (kind 31000, type: credential)
// Create, sign, verify, and parse Signet credentials for all 4 tiers

import { createAttestation } from 'nostr-attestations';
import { ATTESTATION_KIND, ATTESTATION_TYPES, SIGNET_LABEL, DEFAULT_CREDENTIAL_EXPIRY_SECONDS, DEFAULT_CRYPTO_ALGORITHM } from './constants.js';
import { signEvent, verifyEvent, getPublicKey, hash } from './crypto.js';
import { validateCredential, getTagValue, getTagValues } from './validation.js';
import { ringSign, ringVerify, type RingSignature } from './ring-signature.js';
import { createAgeRangeProof, verifyAgeRangeProof, type RangeProof } from './range-proof.js';
import { SignetValidationError } from './errors.js';
import type {
  NostrEvent,
  UnsignedEvent,
  CredentialParams,
  ParsedCredential,
  SignetTier,
  VerificationType,
  VerificationScope,
  VerificationMethod,
  EntityType,
  TwoCredentialResult,
  CredentialChain,
  GuardianDelegationParams,
  MerkleProof,
  CryptoAlgorithm,
} from './types.js';
import { MerkleTree } from './merkle.js';

/** Build an unsigned credential event */
export function buildCredentialEvent(
  verifierPubkey: string,
  params: CredentialParams
): UnsignedEvent {
  const signetTags: string[][] = [
    ['tier', String(params.tier)],
    ['verification-type', params.type],
    ['scope', params.scope],
    ['method', params.method],
    ['algo', DEFAULT_CRYPTO_ALGORITHM],
    ['L', SIGNET_LABEL],
    ['l', 'verification', SIGNET_LABEL],
  ];

  if (params.profession) signetTags.push(['profession', params.profession]);
  if (params.jurisdiction) signetTags.push(['jurisdiction', params.jurisdiction]);
  if (params.ageRange) signetTags.push(['age-range', params.ageRange]);
  if (params.entityType) signetTags.push(['entity-type', params.entityType]);
  if (params.nullifier) signetTags.push(['nullifier', params.nullifier]);
  if (params.merkleRoot) signetTags.push(['merkle-root', params.merkleRoot]);
  if (params.guardianPubkeys) {
    for (const gp of params.guardianPubkeys) {
      signetTags.push(['guardian', gp]);
    }
  }
  if (params.supersedes) signetTags.push(['supersedes', params.supersedes]);

  const template = createAttestation({
    type: ATTESTATION_TYPES.CREDENTIAL,
    identifier: params.subjectPubkey,
    subject: params.subjectPubkey,
    expiration: params.expiresAt,
    occurredAt: params.occurredAt,
    summary: `${params.type} verification (tier ${params.tier}) for ${params.subjectPubkey.slice(0, 8)}...`,
    content: params.content || '',
    tags: signetTags,
  });

  return {
    ...template,
    pubkey: verifierPubkey,
    created_at: Math.floor(Date.now() / 1000),
  };
}

/** Create and sign a Tier 1 (self-declared) credential */
export async function createSelfDeclaredCredential(
  privateKey: string,
  scope: VerificationScope = 'adult',
  expiresAt?: number
): Promise<NostrEvent> {
  const pubkey = getPublicKey(privateKey);
  const event = buildCredentialEvent(pubkey, {
    subjectPubkey: pubkey,
    tier: 1,
    type: 'self',
    scope,
    method: 'self-declaration',
    expiresAt: expiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS,
  });
  return signEvent(event, privateKey);
}

/** Create and sign a Tier 2 (web-of-trust vouched) credential.
 *  Typically issued by a community operator or aggregated from vouches. */
export async function createPeerVouchedCredential(
  issuerPrivateKey: string,
  subjectPubkey: string,
  expiresAt?: number
): Promise<NostrEvent> {
  const pubkey = getPublicKey(issuerPrivateKey);
  const event = buildCredentialEvent(pubkey, {
    subjectPubkey,
    tier: 2,
    type: 'peer',
    scope: 'adult',
    method: 'in-person',
    expiresAt: expiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS,
  });
  return signEvent(event, issuerPrivateKey);
}

/** Create and sign a Tier 3 (professional verified adult) credential */
export async function createProfessionalCredential(
  verifierPrivateKey: string,
  subjectPubkey: string,
  opts: {
    profession: string;
    jurisdiction: string;
    expiresAt?: number;
    occurredAt?: number;
    proofBlob?: string;
  }
): Promise<NostrEvent> {
  const pubkey = getPublicKey(verifierPrivateKey);
  const event = buildCredentialEvent(pubkey, {
    subjectPubkey,
    tier: 3,
    type: 'professional',
    scope: 'adult',
    method: 'in-person-id',
    profession: opts.profession,
    jurisdiction: opts.jurisdiction,
    expiresAt: opts.expiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS,
    occurredAt: opts.occurredAt,
    content: opts.proofBlob,
  });
  return signEvent(event, verifierPrivateKey);
}

/** Create and sign a Tier 4 (professional verified adult+child) credential */
export async function createChildSafetyCredential(
  verifierPrivateKey: string,
  subjectPubkey: string,
  opts: {
    profession: string;
    jurisdiction: string;
    ageRange: string;
    expiresAt?: number;
    occurredAt?: number;
    proofBlob?: string;
  }
): Promise<NostrEvent> {
  const pubkey = getPublicKey(verifierPrivateKey);
  const event = buildCredentialEvent(pubkey, {
    subjectPubkey,
    tier: 4,
    type: 'professional',
    scope: 'adult+child',
    method: 'in-person-id',
    profession: opts.profession,
    jurisdiction: opts.jurisdiction,
    ageRange: opts.ageRange,
    expiresAt: opts.expiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS,
    occurredAt: opts.occurredAt,
    content: opts.proofBlob,
  });
  return signEvent(event, verifierPrivateKey);
}

/** Verify a credential event's signature and structure */
export async function verifyCredential(event: NostrEvent): Promise<{
  signatureValid: boolean;
  structureValid: boolean;
  expired: boolean;
  errors: string[];
}> {
  const signatureValid = await verifyEvent(event);
  const validation = validateCredential(event);
  const expiresStr = getTagValue(event, 'expiration');
  const expired = expiresStr ? (() => { const exp = parseInt(expiresStr, 10); return isNaN(exp) || exp < Math.floor(Date.now() / 1000); })() : false;

  return {
    signatureValid,
    structureValid: validation.valid,
    expired,
    errors: validation.errors,
  };
}

/** Check if a credential is expired */
export function isCredentialExpired(event: NostrEvent): boolean {
  const expiresStr = getTagValue(event, 'expiration');
  if (!expiresStr) return false;
  const exp = parseInt(expiresStr, 10);
  // NaN expiration is treated as expired (not perpetually valid)
  return isNaN(exp) || exp < Math.floor(Date.now() / 1000);
}

/** Parse a credential event into a structured object */
export function parseCredential(event: NostrEvent): ParsedCredential | null {
  if (event.kind !== ATTESTATION_KIND) return null;
  if (getTagValue(event, 'type') !== ATTESTATION_TYPES.CREDENTIAL) return null;

  const tier = getTagValue(event, 'tier');
  if (!tier) return null;

  const guardianValues = getTagValues(event, 'guardian');
  const algorithm = (getTagValue(event, 'algo') || DEFAULT_CRYPTO_ALGORITHM) as CryptoAlgorithm;

  // Strip 'credential:' prefix from d-tag to get subject pubkey
  const dTag = getTagValue(event, 'd') || '';
  const subjectPubkey = dTag.startsWith('credential:') ? dTag.slice('credential:'.length) : dTag;

  return {
    subjectPubkey,
    tier: (() => { const t = parseInt(tier, 10); return (!isNaN(t) && t >= 1 && t <= 4 ? t : 1) as SignetTier; })(),
    type: (getTagValue(event, 'verification-type') || 'self') as VerificationType,
    scope: (getTagValue(event, 'scope') || 'adult') as VerificationScope,
    method: (getTagValue(event, 'method') || 'self-declaration') as VerificationMethod,
    profession: getTagValue(event, 'profession'),
    jurisdiction: getTagValue(event, 'jurisdiction'),
    ageRange: getTagValue(event, 'age-range'),
    expiresAt: (() => { const expiresStr = getTagValue(event, 'expiration'); const expiresNum = expiresStr ? parseInt(expiresStr, 10) : undefined; return (expiresNum !== undefined && !isNaN(expiresNum)) ? expiresNum : undefined; })(),
    entityType: getTagValue(event, 'entity-type') as EntityType | undefined,
    nullifier: getTagValue(event, 'nullifier'),
    merkleRoot: getTagValue(event, 'merkle-root'),
    guardianPubkeys: guardianValues.length > 0 ? guardianValues : undefined,
    supersedes: getTagValue(event, 'supersedes'),
    supersededBy: getTagValue(event, 'superseded-by'),
    occurredAt: (() => { const s = getTagValue(event, 'occurred_at'); const n = s ? parseInt(s, 10) : undefined; return (n !== undefined && !isNaN(n)) ? n : undefined; })(),
    algorithm,
  };
}

// --- Ring Signature Enhanced Credentials (Tier 3/4) ---

/** Content structure for ring-signature-protected credentials */
export interface RingProtectedContent {
  ringSignature: RingSignature;
  rangeProof?: RangeProof;
}

/**
 * Create a Tier 3 credential with ring signature issuer privacy.
 * The credential is signed by the verifier's Nostr key (for relay acceptance),
 * but the content includes a ring signature proving "one of N verifiers" issued it.
 */
export async function createRingProtectedCredential(
  verifierPrivateKey: string,
  subjectPubkey: string,
  ring: string[],
  signerIndex: number,
  opts: {
    profession: string;
    jurisdiction: string;
    expiresAt?: number;
  }
): Promise<NostrEvent> {
  const pubkey = getPublicKey(verifierPrivateKey);
  const expiresAt = opts.expiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS;

  // Use a single timestamp for both the ring signature binding and the event
  const timestamp = Math.floor(Date.now() / 1000);

  // Ring signature binds to subject + timestamp (not event ID, which changes with content)
  const ringSig = ringSign(
    `signet:credential:${subjectPubkey}:${timestamp}`,
    ring,
    signerIndex,
    verifierPrivateKey
  );

  const content: RingProtectedContent = { ringSignature: ringSig };

  const event: UnsignedEvent = {
    kind: ATTESTATION_KIND,
    pubkey,
    created_at: timestamp,
    tags: buildCredentialEvent(pubkey, {
      subjectPubkey,
      tier: 3,
      type: 'professional',
      scope: 'adult',
      method: 'in-person-id',
      profession: opts.profession,
      jurisdiction: opts.jurisdiction,
      expiresAt,
      content: JSON.stringify(content),
    }).tags,
    content: JSON.stringify(content),
  };

  return signEvent(event, verifierPrivateKey);
}

/**
 * Create a Tier 4 credential with ring signature AND age range proof.
 */
export async function createRingProtectedChildCredential(
  verifierPrivateKey: string,
  subjectPubkey: string,
  ring: string[],
  signerIndex: number,
  opts: {
    profession: string;
    jurisdiction: string;
    ageRange: string;
    actualAge: number;
    expiresAt?: number;
  }
): Promise<NostrEvent> {
  const pubkey = getPublicKey(verifierPrivateKey);
  const expiresAt = opts.expiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS;

  // Use a single timestamp for both the ring signature binding and the event
  const timestamp = Math.floor(Date.now() / 1000);

  // Create the age range proof, bound to the subject pubkey to prevent transplanting
  const rangeProof = createAgeRangeProof(opts.actualAge, opts.ageRange, subjectPubkey);

  // Ring signature binds to subject + timestamp (not event ID, which changes with content)
  const ringSig = ringSign(
    `signet:credential:${subjectPubkey}:${timestamp}`,
    ring,
    signerIndex,
    verifierPrivateKey
  );

  const content: RingProtectedContent = {
    ringSignature: ringSig,
    rangeProof,
  };

  const event: UnsignedEvent = {
    kind: ATTESTATION_KIND,
    pubkey,
    created_at: timestamp,
    tags: buildCredentialEvent(pubkey, {
      subjectPubkey,
      tier: 4,
      type: 'professional',
      scope: 'adult+child',
      method: 'in-person-id',
      profession: opts.profession,
      jurisdiction: opts.jurisdiction,
      ageRange: opts.ageRange,
      expiresAt,
      content: JSON.stringify(content),
    }).tags,
    content: JSON.stringify(content),
  };

  return signEvent(event, verifierPrivateKey);
}

/**
 * Verify the ring signature and optional range proof inside a credential's content.
 */
export function verifyRingProtectedContent(event: NostrEvent): {
  hasRingSignature: boolean;
  ringValid: boolean;
  hasRangeProof: boolean;
  rangeProofValid: boolean;
} {
  const result = {
    hasRingSignature: false,
    ringValid: false,
    hasRangeProof: false,
    rangeProofValid: false,
  };

  if (!event.content) return result;

  try {
    const raw = JSON.parse(event.content);
    if (!raw || typeof raw !== 'object') return result;
    const content = raw as RingProtectedContent;
    const dTag = getTagValue(event, 'd') || '';
    const subjectPubkey = dTag.startsWith('credential:') ? dTag.slice('credential:'.length) : dTag;

    if (content.ringSignature &&
        typeof content.ringSignature === 'object' &&
        typeof content.ringSignature.message === 'string' &&
        Array.isArray(content.ringSignature.ring) &&
        content.ringSignature.ring.every((r: unknown) => typeof r === 'string') &&
        typeof content.ringSignature.c0 === 'string' &&
        Array.isArray(content.ringSignature.responses) &&
        content.ringSignature.responses.every((r: unknown) => typeof r === 'string')) {
      result.hasRingSignature = true;

      // Verify the ring signature is cryptographically valid
      const cryptoValid = ringVerify(content.ringSignature);

      // Verify the binding message references this credential's subject
      const expectedPrefix = `signet:credential:${subjectPubkey}:`;
      const messageBindsToSubject = content.ringSignature.message.startsWith(expectedPrefix);

      // Extract timestamp from after the validated prefix
      const timestampStr = content.ringSignature.message.slice(expectedPrefix.length);
      const msgTimestamp = parseInt(timestampStr, 10);
      const timestampMatches = !isNaN(msgTimestamp) && msgTimestamp === event.created_at;

      result.ringValid = cryptoValid && messageBindsToSubject && timestampMatches;
    }

    if (content.rangeProof &&
        typeof content.rangeProof === 'object' &&
        !Array.isArray(content.rangeProof)) {
      result.hasRangeProof = true;
      const expectedAgeRange = getTagValue(event, 'age-range');
      if (!expectedAgeRange) {
        result.rangeProofValid = false;
      } else {
        result.rangeProofValid = verifyAgeRangeProof(content.rangeProof, expectedAgeRange, subjectPubkey);
      }
    }
  } catch {
    // Content is not JSON or not a RingProtectedContent — that's OK for Tier 1/2
  }

  return result;
}

// --- Credential Renewal ---

/**
 * Renew an expiring credential. Creates a new credential with the same parameters
 * but a fresh expiry. Must be issued by the same verifier (or a new one for re-verification).
 */
export async function renewCredential(
  verifierPrivateKey: string,
  existingCredential: NostrEvent,
  newExpiresAt?: number
): Promise<NostrEvent> {
  const parsed = parseCredential(existingCredential);
  if (!parsed) throw new SignetValidationError('Invalid credential to renew');

  const pubkey = getPublicKey(verifierPrivateKey);
  const expiresAt = newExpiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS;

  const event = buildCredentialEvent(pubkey, {
    subjectPubkey: parsed.subjectPubkey,
    tier: parsed.tier,
    type: parsed.type,
    scope: parsed.scope,
    method: parsed.method,
    profession: parsed.profession,
    jurisdiction: parsed.jurisdiction,
    ageRange: parsed.ageRange,
    expiresAt,
  });

  return signEvent(event, verifierPrivateKey);
}

/**
 * Check if a credential needs renewal (within N days of expiry).
 */
export function needsRenewal(event: NostrEvent, withinDays: number = 30): boolean {
  if (withinDays < 0) throw new SignetValidationError('withinDays must be non-negative');
  const expiresStr = getTagValue(event, 'expiration');
  if (!expiresStr) return false;

  const expiresAt = parseInt(expiresStr, 10);
  if (isNaN(expiresAt)) return false;
  const now = Math.floor(Date.now() / 1000);
  const threshold = now + withinDays * 24 * 60 * 60;

  return expiresAt <= threshold;
}

// --- Two-Credential Ceremony ---

/**
 * Create a two-credential ceremony issuing Natural Person + Persona credentials.
 * The verifier sees all documents but only publishes privacy-preserving tags.
 */
export async function createTwoCredentialCeremony(
  verifierPrivateKey: string,
  naturalPersonPubkey: string,
  personaPubkey: string,
  opts: {
    name: string;
    nationality: string;
    documentType: string;
    documentNumber: string;
    documentCountry: string;
    dateOfBirth: string; // ISO date
    profession: string;
    jurisdiction: string;
    ageRange?: string;
    guardianPubkeys?: string[];
    expiresAt?: number;
    occurredAt?: number;
  }
): Promise<TwoCredentialResult> {
  const verifierPubkey = getPublicKey(verifierPrivateKey);
  const expiresAt = opts.expiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS;

  // 1. Compute nullifier from document details (NOT published, only hash)
  const nullifier = computeNullifier(opts.documentType, opts.documentCountry, opts.documentNumber);

  // 2. Build Merkle tree from verified attributes
  const merkleLeaves: Record<string, string> = {
    name: opts.name,
    nationality: opts.nationality,
    documentType: opts.documentType,
    dateOfBirth: opts.dateOfBirth,
    nullifier: nullifier,
  };
  const tree = new MerkleTree(merkleLeaves);
  const merkleRoot = tree.getRoot();

  // 3. Compute age range from DOB if not provided
  const VALID_AGE_RANGES = ['0-3', '4-7', '8-12', '13-17', '18+'];
  const ageRange = opts.ageRange || computeAgeRange(opts.dateOfBirth);
  if (!VALID_AGE_RANGES.includes(ageRange)) {
    throw new SignetValidationError(`Invalid age range: must be one of ${VALID_AGE_RANGES.join(', ')}`);
  }

  // 4. Determine tier and scope
  const isChild = ageRange !== '18+';
  const tier: SignetTier = isChild ? 4 : 3;
  const scope: VerificationScope = isChild ? 'adult+child' : 'adult';

  // 5. Issue Natural Person credential (keypair A)
  const npEvent = buildCredentialEvent(verifierPubkey, {
    subjectPubkey: naturalPersonPubkey,
    tier,
    type: 'professional',
    scope,
    method: 'in-person-id',
    profession: opts.profession,
    jurisdiction: opts.jurisdiction,
    ageRange,
    entityType: 'natural_person',
    nullifier,
    merkleRoot,
    guardianPubkeys: opts.guardianPubkeys,
    expiresAt,
    occurredAt: opts.occurredAt,
  });
  const naturalPerson = await signEvent(npEvent, verifierPrivateKey);

  // 6. Issue Persona credential (keypair B) — NO nullifier, NO merkle-root
  const personaEvent = buildCredentialEvent(verifierPubkey, {
    subjectPubkey: personaPubkey,
    tier,
    type: 'professional',
    scope,
    method: 'in-person-id',
    profession: opts.profession,
    jurisdiction: opts.jurisdiction,
    ageRange,
    entityType: 'persona',
    guardianPubkeys: opts.guardianPubkeys,
    expiresAt,
    occurredAt: opts.occurredAt,
  });
  const persona = await signEvent(personaEvent, verifierPrivateKey);

  // 7. Generate Merkle proofs for all leaves
  const merkleProofs: MerkleProof[] = Object.keys(merkleLeaves)
    .sort()
    .map((key) => tree.prove(key));

  return {
    naturalPerson,
    persona,
    merkleLeaves,
    merkleProofs,
  };
}

/** Compute age range string from ISO date of birth */
function computeAgeRange(dateOfBirth: string): string {
  const dob = new Date(dateOfBirth);
  if (isNaN(dob.getTime())) throw new SignetValidationError('Invalid date of birth: value is not a parseable ISO date');
  const now = new Date();
  let age = now.getFullYear() - dob.getFullYear();
  const monthDiff = now.getMonth() - dob.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && now.getDate() < dob.getDate())) {
    age--;
  }
  if (age < 0 || age > 150) {
    throw new SignetValidationError(`Implausible age ${age} computed from date of birth`);
  }

  if (age >= 18) return '18+';
  if (age >= 13) return '13-17';
  if (age >= 8) return '8-12';
  if (age >= 4) return '4-7';
  return '0-3';
}

// --- Credential Chains ---

/**
 * Issue a new credential that supersedes an existing one.
 * The old credential gets a superseded-by tag added (returned as updated event).
 */
export async function supersedeCredential(
  verifierPrivateKey: string,
  oldCredential: NostrEvent,
  newParams: Partial<CredentialParams> & { subjectPubkey: string }
): Promise<{ newCredential: NostrEvent; oldCredential: NostrEvent }> {
  const parsed = parseCredential(oldCredential);
  if (!parsed) throw new SignetValidationError('Invalid credential to supersede');

  const verifierPubkey = getPublicKey(verifierPrivateKey);
  const expiresAt = newParams.expiresAt || Math.floor(Date.now() / 1000) + DEFAULT_CREDENTIAL_EXPIRY_SECONDS;

  // Build new credential with supersedes link
  const newEvent = buildCredentialEvent(verifierPubkey, {
    subjectPubkey: newParams.subjectPubkey,
    tier: newParams.tier || parsed.tier,
    type: newParams.type || parsed.type,
    scope: newParams.scope || parsed.scope,
    method: newParams.method || parsed.method,
    profession: newParams.profession ?? parsed.profession,
    jurisdiction: newParams.jurisdiction ?? parsed.jurisdiction,
    ageRange: newParams.ageRange ?? parsed.ageRange,
    entityType: newParams.entityType ?? parsed.entityType,
    nullifier: newParams.nullifier ?? parsed.nullifier,
    merkleRoot: newParams.merkleRoot ?? parsed.merkleRoot,
    guardianPubkeys: newParams.guardianPubkeys ?? parsed.guardianPubkeys,
    supersedes: oldCredential.id,
    expiresAt,
  });

  const newCredential = await signEvent(newEvent, verifierPrivateKey);

  // Note: We do NOT modify the old credential. Adding a tag would invalidate its
  // id and signature (which are computed from the serialized event including tags).
  // The supersession relationship is established by the 'supersedes' tag on the
  // new credential pointing to the old credential's id.

  return { newCredential, oldCredential };
}

const MAX_CHAIN_DEPTH = 100;

/**
 * Follow supersedes/superseded-by chain to find current active credential.
 */
export function resolveCredentialChain(events: NostrEvent[]): CredentialChain | null {
  if (events.length === 0) return null;

  // Build lookup maps
  const byId = new Map<string, NostrEvent>();
  for (const e of events) byId.set(e.id, e);

  // Build a set of all IDs that are superseded by another event in the set
  const supersededIds = new Set<string>();
  for (const e of events) {
    const supersedesId = getTagValue(e, 'supersedes');
    if (supersedesId && byId.has(supersedesId)) {
      supersededIds.add(supersedesId);
    }
  }

  // The "current" credential is the one whose ID is NOT in the superseded set
  let current: NostrEvent | undefined;
  for (const e of events) {
    if (!supersededIds.has(e.id)) {
      current = e;
    }
  }
  if (!current) current = events[events.length - 1];

  // Walk backwards through supersedes links to build history
  const history: NostrEvent[] = [];
  let cursor: NostrEvent | undefined = current;
  const visited = new Set<string>();

  while (cursor) {
    if (visited.has(cursor.id)) break;
    if (history.length >= MAX_CHAIN_DEPTH) break;
    visited.add(cursor.id);

    const supersedesId = getTagValue(cursor, 'supersedes');
    if (supersedesId && byId.has(supersedesId)) {
      history.unshift(byId.get(supersedesId)!);
      cursor = byId.get(supersedesId);
    } else {
      break;
    }
  }

  return { current, history };
}

/**
 * Check if a credential has been superseded.
 */
export function isSuperseded(event: NostrEvent): boolean {
  return !!getTagValue(event, 'superseded-by');
}

// --- Nullifier Utilities ---

/**
 * Compute a deterministic nullifier from document details.
 * Uses length-prefixed encoding to prevent field-boundary collisions:
 *   SHA-256( len(docType) + docType + len(country) + country + len(docNum) + docNum + domainTag )
 *
 * Each field is prefixed with its UTF-8 byte length as a 2-byte big-endian uint16,
 * followed by a fixed domain separation tag.
 */
export function computeNullifier(documentType: string, countryCode: string, documentNumber: string): string {
  const domainTag = 'signet-nullifier-v2';
  const fields = [documentType, countryCode, documentNumber, domainTag];

  // Calculate total buffer size: 2 bytes length prefix + field bytes for each field
  const encoder = new TextEncoder();
  const encoded = fields.map(f => encoder.encode(f));
  const totalLen = encoded.reduce((sum, buf) => sum + 2 + buf.length, 0);

  const buffer = new Uint8Array(totalLen);
  let offset = 0;
  for (const fieldBytes of encoded) {
    // 2-byte big-endian length prefix
    buffer[offset] = (fieldBytes.length >> 8) & 0xff;
    buffer[offset + 1] = fieldBytes.length & 0xff;
    offset += 2;
    buffer.set(fieldBytes, offset);
    offset += fieldBytes.length;
  }

  return hash(buffer);
}

/**
 * Check if a nullifier already exists in a set of credentials.
 * Returns the conflicting credential if found.
 */
export function checkNullifierDuplicate(
  nullifier: string,
  existingCredentials: NostrEvent[]
): { isDuplicate: boolean; conflicting?: NostrEvent } {
  for (const cred of existingCredentials) {
    const credNullifier = getTagValue(cred, 'nullifier');
    if (credNullifier === nullifier) {
      return { isDuplicate: true, conflicting: cred };
    }
  }
  return { isDuplicate: false };
}

/**
 * Build a nullifier-chain tag linking old and new nullifiers (for document renewal).
 */
export function buildNullifierChainTag(oldNullifier: string): string[][] {
  return [['nullifier-chain', oldNullifier]];
}

// --- Multi-Document Nullifier Families ---

export interface DocumentDescriptor {
  documentType: string;
  countryCode: string;
  documentNumber: string;
}

export interface NullifierFamily {
  /** Primary nullifier (first document) */
  primary: string;
  /** All nullifiers in the family (including primary) */
  nullifiers: Array<{ documentType: string; nullifier: string }>;
}

/**
 * Compute nullifiers for ALL documents presented during a verification ceremony.
 * Returns a nullifier family containing all nullifiers. Collision with ANY nullifier
 * in ANY family triggers duplicate detection.
 */
export function computeNullifierFamily(documents: DocumentDescriptor[]): NullifierFamily {
  if (documents.length === 0) {
    throw new SignetValidationError('At least one document is required for nullifier computation');
  }

  const nullifiers = documents.map(doc => ({
    documentType: doc.documentType,
    nullifier: computeNullifier(doc.documentType, doc.countryCode, doc.documentNumber),
  }));

  return {
    primary: nullifiers[0].nullifier,
    nullifiers,
  };
}

/**
 * Build nullifier-family tags for a credential event.
 * The primary nullifier is stored in the 'nullifier' tag (backwards compatible).
 * Additional nullifiers are stored in 'nullifier-family' tags.
 */
export function buildNullifierFamilyTags(family: NullifierFamily): string[][] {
  const tags: string[][] = [
    ['nullifier', family.primary],
  ];
  for (const entry of family.nullifiers) {
    tags.push(['nullifier-family', entry.nullifier, entry.documentType]);
  }
  return tags;
}

/**
 * Check if ANY nullifier in a family collides with ANY nullifier in existing credentials.
 * This catches attempts to use different documents for the same person.
 */
export function checkNullifierFamilyDuplicate(
  family: NullifierFamily,
  existingCredentials: NostrEvent[]
): { isDuplicate: boolean; conflicting?: NostrEvent; matchedNullifier?: string } {
  for (const cred of existingCredentials) {
    // Check against primary nullifier tag
    const credNullifier = getTagValue(cred, 'nullifier');

    // Also check against all nullifier-family tags
    const credFamilyNullifiers = getTagValues(cred, 'nullifier-family');

    const allCredNullifiers = new Set<string>();
    if (credNullifier) allCredNullifiers.add(credNullifier);
    for (const fn of credFamilyNullifiers) {
      allCredNullifiers.add(fn);
    }

    // Check each nullifier in the new family against all existing nullifiers
    for (const entry of family.nullifiers) {
      if (allCredNullifiers.has(entry.nullifier)) {
        return { isDuplicate: true, conflicting: cred, matchedNullifier: entry.nullifier };
      }
    }
  }

  return { isDuplicate: false };
}

// --- Guardian Delegation ---

/**
 * Create a guardian delegation event (kind 31000, type: delegation).
 * Allows a guardian to delegate specific permissions to another adult for a child.
 */
export async function createGuardianDelegation(
  guardianPrivateKey: string,
  params: GuardianDelegationParams
): Promise<NostrEvent> {
  const guardianPubkey = getPublicKey(guardianPrivateKey);

  const signetTags: string[][] = [
    ['p', params.delegatePubkey],
    ['delegation-type', 'guardian-delegate'],
    ['child', params.childPubkey],
    ['scope', params.scope],
    ['algo', DEFAULT_CRYPTO_ALGORITHM],
    ['L', SIGNET_LABEL],
    ['l', 'delegation', SIGNET_LABEL],
  ];

  const template = createAttestation({
    type: ATTESTATION_TYPES.DELEGATION,
    identifier: `${params.childPubkey}:${params.delegatePubkey}`,
    subject: params.delegatePubkey,
    expiration: params.expiresAt,
    summary: `Guardian delegation for ${params.childPubkey.slice(0, 8)}... to ${params.delegatePubkey.slice(0, 8)}...`,
    content: '',
    tags: signetTags,
  });

  const event = {
    ...template,
    pubkey: guardianPubkey,
    created_at: Math.floor(Date.now() / 1000),
  };

  return signEvent(event, guardianPrivateKey);
}
