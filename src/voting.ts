// Signet Voting Protocol
// Election creation, ballot casting with LSAG ring signatures, and tallying.

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils';
import { generateKeyPair as genKey, getPublicKey, signEvent } from './crypto.js';
import { SIGNET_KINDS, SIGNET_LABEL, DEFAULT_CRYPTO_ALGORITHM } from './constants.js';
import { getTagValue, validateFieldSizeBounds } from './validation.js';
import type { ValidationResult } from './validation.js';
import { computeKeyImage, lsagSign, lsagVerify } from './lsag.js';
import { SignetVotingError, SignetCryptoError, SignetValidationError } from './errors.js';
import type { LsagSignature } from './lsag.js';
import type {
  NostrEvent, UnsignedEvent, ElectionParams, ParsedElection,
  ElectionScale, ReVotePolicy, EntityType, SignetTier,
} from './types.js';

// ---------------------------------------------------------------------------
// Task 6: Election creation and parsing
// ---------------------------------------------------------------------------

/**
 * Create a kind 30482 Election Definition event.
 *
 * @param authorityPrivateKey - hex private key of the election authority
 * @param params - election parameters
 * @returns signed NostrEvent
 */
export async function createElection(
  authorityPrivateKey: string,
  params: ElectionParams,
): Promise<NostrEvent> {
  // Validations
  if (params.options.length < 2) {
    throw new SignetVotingError('Election must have at least 2 options');
  }
  if (params.closes <= params.opens) {
    throw new SignetVotingError('Election closing time must be after opening time');
  }
  if (params.tallyPubkeys.length < 1) {
    throw new SignetVotingError('Election must have at least 1 tally pubkey');
  }

  const pubkey = getPublicKey(authorityPrivateKey);

  const tags: string[][] = [
    ['d', params.electionId],
    ['title', params.title],
    ['scale', params.scale],
    ['opens', String(params.opens)],
    ['closes', String(params.closes)],
    ['re-vote', params.reVote],
    ['algo', DEFAULT_CRYPTO_ALGORITHM],
    ['L', SIGNET_LABEL],
    ['l', SIGNET_LABEL],
  ];

  if (params.description) {
    tags.push(['description', params.description]);
  }

  for (const option of params.options) {
    tags.push(['option', option]);
  }

  for (const entityType of params.eligibleEntityTypes) {
    tags.push(['eligible-entity-type', entityType]);
  }

  tags.push(['eligible-min-tier', String(params.eligibleMinTier)]);

  if (params.eligibleCommunity) {
    tags.push(['eligible-community', params.eligibleCommunity]);
  }

  for (const pk of params.tallyPubkeys) {
    tags.push(['tally-pubkey', pk]);
  }

  if (params.tallyThreshold) {
    const [m, n] = params.tallyThreshold;
    tags.push(['tally-threshold', `${m}/${n}`]);
  }

  if (params.ringSize !== undefined) {
    tags.push(['ring-size', String(params.ringSize)]);
  }

  const unsigned: UnsignedEvent = {
    kind: SIGNET_KINDS.ELECTION,
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: '',
  };

  return signEvent(unsigned, authorityPrivateKey);
}

/**
 * Parse a kind 30482 Election Definition event into structured data.
 *
 * @returns ParsedElection or null if the event is not a valid election
 */
export function parseElection(event: NostrEvent): ParsedElection | null {
  if (event.kind !== SIGNET_KINDS.ELECTION) return null;

  const electionId = getTagValue(event, 'd');
  const title = getTagValue(event, 'title');
  const scale = getTagValue(event, 'scale') as ElectionScale | undefined;
  const opensStr = getTagValue(event, 'opens');
  const closesStr = getTagValue(event, 'closes');
  const reVote = getTagValue(event, 're-vote') as ReVotePolicy | undefined;
  const algorithm = getTagValue(event, 'algo') ?? DEFAULT_CRYPTO_ALGORITHM;

  if (!electionId || !title || !scale || !opensStr || !closesStr || !reVote) {
    return null;
  }

  const options = event.tags.filter((t) => t[0] === 'option').map((t) => t[1]);
  if (options.length < 2) return null;

  const tallyPubkeys = event.tags.filter((t) => t[0] === 'tally-pubkey').map((t) => t[1]);
  if (tallyPubkeys.length < 1) return null;

  const eligibleEntityTypes = event.tags
    .filter((t) => t[0] === 'eligible-entity-type')
    .map((t) => t[1] as EntityType);

  const eligibleMinTierStr = getTagValue(event, 'eligible-min-tier');
  const rawMinTier = eligibleMinTierStr ? parseInt(eligibleMinTierStr, 10) : 1;
  const eligibleMinTier = (rawMinTier >= 1 && rawMinTier <= 4 ? rawMinTier : 1) as SignetTier;

  const description = getTagValue(event, 'description');
  const eligibleCommunity = getTagValue(event, 'eligible-community');

  let tallyThreshold: [number, number] | undefined;
  const thresholdStr = getTagValue(event, 'tally-threshold');
  if (thresholdStr) {
    const parts = thresholdStr.split('/');
    if (parts.length === 2) {
      const m = parseInt(parts[0], 10);
      const n = parseInt(parts[1], 10);
      if (isNaN(m) || isNaN(n) || m < 1 || n < 1 || m > n) return null;
      tallyThreshold = [m, n];
    }
  }

  const ringSizeStr = getTagValue(event, 'ring-size');
  let ringSize = ringSizeStr ? parseInt(ringSizeStr, 10) : undefined;
  if (ringSize !== undefined && (isNaN(ringSize) || ringSize < 2 || ringSize > 1000)) {
    return null; // ring size must be valid and within MAX_RING_SIZE
  }

  const opens = parseInt(opensStr, 10);
  const closes = parseInt(closesStr, 10);
  if (isNaN(opens) || isNaN(closes)) return null;

  if (isNaN(eligibleMinTier)) return null;

  const parsed: ParsedElection = {
    electionId,
    title,
    options,
    scale,
    eligibleEntityTypes,
    eligibleMinTier,
    opens,
    closes,
    reVote,
    tallyPubkeys,
    authorityPubkey: event.pubkey,
    algorithm,
  };

  if (description) parsed.description = description;
  if (eligibleCommunity) parsed.eligibleCommunity = eligibleCommunity;
  if (tallyThreshold) parsed.tallyThreshold = tallyThreshold;
  if (ringSize !== undefined) parsed.ringSize = ringSize;

  return parsed;
}

// ---------------------------------------------------------------------------
// Task 7: Ballot encryption helpers
// ---------------------------------------------------------------------------

/**
 * Encrypt ballot content for a tally pubkey using ECDH + HKDF + AES-256-GCM.
 *
 * Output format: ephemeralPubkey (64 hex) + nonce (24 hex) + ciphertext+tag (variable hex)
 */
export async function encryptBallotContent(
  plaintext: string,
  tallyPubkey: string,
): Promise<string> {
  // Generate ephemeral keypair
  const ephemeral = genKey();

  // ECDH: ephemeralPriv * tallyPub (prepend '02' to x-only pubkey)
  const tallyPoint = secp256k1.ProjectivePoint.fromHex('02' + tallyPubkey);
  const ephScalar = BigInt('0x' + ephemeral.privateKey) % secp256k1.CURVE.n;
  if (ephScalar === 0n) {
    throw new SignetCryptoError('Ephemeral private key is zero — cannot perform ECDH');
  }
  const sharedPoint = tallyPoint.multiply(ephScalar);
  if (sharedPoint.equals(secp256k1.ProjectivePoint.ZERO)) {
    throw new SignetCryptoError('ECDH produced identity point — invalid public key');
  }
  const sharedX = sharedPoint.toAffine().x;
  // SHA-256 of x-coordinate
  const sharedXBytes = hexToBytes(sharedX.toString(16).padStart(64, '0'));
  const sharedSecret = sha256(sharedXBytes);

  // HKDF-SHA256 to derive AES key
  const aesKey = hkdf(sha256, sharedSecret, new Uint8Array(0), 'signet-ballot-encrypt-v1', 32);

  // AES-256-GCM encryption
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey(
    'raw', new Uint8Array(aesKey), { name: 'AES-GCM' }, false, ['encrypt'],
  );
  const plaintextBytes = utf8ToBytes(plaintext);
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    cryptoKey,
    new Uint8Array(plaintextBytes),
  );
  const ciphertext = new Uint8Array(ciphertextBuf);

  // Output: ephemeralPubkey (64 hex) + nonce (24 hex) + ciphertext+tag (variable hex)
  return ephemeral.publicKey + bytesToHex(nonce) + bytesToHex(ciphertext);
}

/**
 * Decrypt ballot content using the tally private key.
 *
 * Input format: ephemeralPubkey (64 hex) + nonce (24 hex) + ciphertext+tag (variable hex)
 */
export async function decryptBallotContent(
  encrypted: string,
  tallyPrivateKey: string,
): Promise<string> {
  // Minimum: ephemeralPubkey (64 hex) + nonce (24 hex) + AES-GCM tag (32 hex) = 120
  if (encrypted.length < 120) {
    throw new SignetValidationError('Encrypted ballot content too short');
  }

  // Parse components
  const ephemeralPubkeyHex = encrypted.slice(0, 64);
  const nonceHex = encrypted.slice(64, 88);
  const ciphertextHex = encrypted.slice(88);

  const nonce = hexToBytes(nonceHex);
  const ciphertext = hexToBytes(ciphertextHex);

  // ECDH: tallyPriv * ephemeralPub
  const ephemeralPoint = secp256k1.ProjectivePoint.fromHex('02' + ephemeralPubkeyHex);
  const tallyScalar = BigInt('0x' + tallyPrivateKey) % secp256k1.CURVE.n;
  if (tallyScalar === 0n) {
    throw new SignetCryptoError('Invalid tally private key (zero after mod N reduction)');
  }
  const sharedPoint = ephemeralPoint.multiply(tallyScalar);
  if (sharedPoint.equals(secp256k1.ProjectivePoint.ZERO)) {
    throw new SignetCryptoError('ECDH produced identity point — invalid public key');
  }
  const sharedX = sharedPoint.toAffine().x;
  const sharedXBytes = hexToBytes(sharedX.toString(16).padStart(64, '0'));
  const sharedSecret = sha256(sharedXBytes);

  // HKDF-SHA256 to derive AES key
  const aesKey = hkdf(sha256, sharedSecret, new Uint8Array(0), 'signet-ballot-encrypt-v1', 32);

  // AES-256-GCM decryption
  const cryptoKey = await crypto.subtle.importKey(
    'raw', new Uint8Array(aesKey), { name: 'AES-GCM' }, false, ['decrypt'],
  );
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(nonce) },
    cryptoKey,
    new Uint8Array(ciphertext),
  );

  return new TextDecoder().decode(plaintextBuf);
}

// ---------------------------------------------------------------------------
// Task 8: Ballot casting and verification
// ---------------------------------------------------------------------------

/**
 * Cast a ballot in an election using LSAG ring signatures for voter anonymity.
 *
 * @param voterPrivateKey - voter's private key (hex)
 * @param election - the signed election event
 * @param selectedOption - the option the voter selects
 * @param eligibleRing - array of x-only pubkeys forming the eligible voter ring
 * @returns the signed ballot event and the ephemeral pubkey used
 */
export async function castBallot(
  voterPrivateKey: string,
  election: NostrEvent,
  selectedOption: string,
  eligibleRing: string[],
): Promise<{ event: NostrEvent; ephemeralPubkey: string }> {
  const parsed = parseElection(election);
  if (!parsed) throw new SignetVotingError('Invalid election event');

  const voterPubkey = getPublicKey(voterPrivateKey);

  // Validate voter is in the ring
  const signerIndex = eligibleRing.indexOf(voterPubkey);
  if (signerIndex === -1) {
    throw new SignetVotingError('Voter public key not found in eligible ring');
  }

  // Validate selected option
  if (!parsed.options.includes(selectedOption)) {
    throw new SignetVotingError('Selected option is not valid for this election');
  }

  // Validate election is open
  const now = Math.floor(Date.now() / 1000);
  if (now < parsed.opens) {
    throw new SignetVotingError('Election has not yet opened');
  }
  if (now >= parsed.closes) {
    throw new SignetVotingError('Election has already closed');
  }

  // Compute key image
  const keyImage = computeKeyImage(voterPrivateKey, voterPubkey, parsed.electionId);

  // Encrypt vote content to first tally pubkey BEFORE signing —
  // the LSAG signs a commitment to the ciphertext, not the plaintext vote.
  const voteContent = JSON.stringify({ option: selectedOption });
  const encryptedVote = await encryptBallotContent(voteContent, parsed.tallyPubkeys[0]);

  // LSAG signs "electionId:sha256(encryptedVote)" — binds the signature
  // to the specific ciphertext without revealing the vote.
  const voteHash = bytesToHex(sha256(utf8ToBytes(encryptedVote)));
  const message = `${parsed.electionId}:${voteHash}`;
  const ringSig = lsagSign(message, eligibleRing, signerIndex, voterPrivateKey, parsed.electionId);

  // Generate ephemeral keypair for ballot event
  const ephemeral = genKey();

  const tags: string[][] = [
    ['d', `${parsed.electionId}:${bytesToHex(randomBytes(16))}`],
    ['election', election.id],
    ['key-image', keyImage],
    ['ring-sig', JSON.stringify(ringSig)],
    ['encrypted-vote', encryptedVote],
    ['algo', DEFAULT_CRYPTO_ALGORITHM],
    ['L', SIGNET_LABEL],
    ['l', SIGNET_LABEL],
  ];

  const unsigned: UnsignedEvent = {
    kind: SIGNET_KINDS.BALLOT,
    pubkey: ephemeral.publicKey,
    created_at: now,
    tags,
    content: '',
  };

  const event = await signEvent(unsigned, ephemeral.privateKey);
  return { event, ephemeralPubkey: ephemeral.publicKey };
}

/**
 * Verify a ballot event against an election and eligible ring.
 * Does NOT check key image uniqueness (that is the tally's job).
 */
export function verifyBallot(
  ballot: NostrEvent,
  election: NostrEvent,
  eligibleRing: string[],
): ValidationResult {
  const errors: string[] = [];

  if (ballot.kind !== SIGNET_KINDS.BALLOT) {
    errors.push(`Expected kind ${SIGNET_KINDS.BALLOT}, got ${ballot.kind}`);
  }

  const parsed = parseElection(election);
  if (!parsed) {
    errors.push('Invalid election event');
    return { valid: false, errors };
  }

  // Check election reference
  const electionRef = getTagValue(ballot, 'election');
  if (electionRef !== election.id) {
    errors.push('Ballot election reference does not match election event ID');
  }

  // Check time window
  if (ballot.created_at < parsed.opens) {
    errors.push('Ballot was created before election opened');
  }
  if (ballot.created_at >= parsed.closes) {
    errors.push('Ballot was created after election closed');
  }

  // Reject ballots with timestamps in the future (prevents created_at spoofing)
  const now = Math.floor(Date.now() / 1000);
  if (ballot.created_at > now + 60) {
    errors.push('Ballot timestamp is in the future');
  }

  // Parse ring signature
  const ringSigStr = getTagValue(ballot, 'ring-sig');
  if (!ringSigStr) {
    errors.push('Missing ring-sig tag');
    return { valid: errors.length === 0, errors };
  }

  let ringSig: LsagSignature;
  try {
    const raw = JSON.parse(ringSigStr);
    if (!raw || typeof raw !== 'object' || !Array.isArray(raw.ring) ||
        typeof raw.message !== 'string' || typeof raw.c0 !== 'string' ||
        !Array.isArray(raw.responses) || typeof raw.keyImage !== 'string' ||
        typeof raw.electionId !== 'string') {
      errors.push('Invalid ring-sig structure');
      return { valid: false, errors };
    }
    ringSig = raw as LsagSignature;
  } catch {
    errors.push('Invalid ring-sig JSON');
    return { valid: false, errors };
  }

  // Verify ring matches eligible ring
  if (JSON.stringify(ringSig.ring) !== JSON.stringify(eligibleRing)) {
    errors.push('Ring in signature does not match eligible ring');
  }

  // Verify election ID in signature matches
  if (ringSig.electionId !== parsed.electionId) {
    errors.push('Election ID in ring signature does not match election');
  }

  // Verify LSAG signature
  if (!lsagVerify(ringSig)) {
    errors.push('LSAG ring signature verification failed');
  }

  // Verify LSAG message is bound to the encrypted vote (not plaintext)
  const encryptedVote = getTagValue(ballot, 'encrypted-vote');
  if (!encryptedVote) {
    errors.push('Missing encrypted-vote tag');
  } else {
    const expectedHash = bytesToHex(sha256(utf8ToBytes(encryptedVote)));
    const expectedMessage = `${parsed.electionId}:${expectedHash}`;
    if (ringSig.message !== expectedMessage) {
      errors.push('Ring signature message does not match encrypted vote commitment');
    }
  }

  // Verify key-image tag matches signature
  const keyImageTag = getTagValue(ballot, 'key-image');
  if (keyImageTag !== ringSig.keyImage) {
    errors.push('Key image tag does not match ring signature key image');
  }

  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Task 9: Election tally
// ---------------------------------------------------------------------------

/**
 * Tally election results: verify ballots, deduplicate, decrypt, and count.
 *
 * @param ballots - array of ballot events
 * @param election - the election event
 * @param tallyPrivateKey - private key of the tally authority
 * @param eligibleRing - the eligible voter ring
 * @returns signed kind 30484 election result event
 */
export async function tallyElection(
  ballots: NostrEvent[],
  election: NostrEvent,
  tallyPrivateKey: string,
  eligibleRing: string[],
): Promise<NostrEvent> {
  const parsed = parseElection(election);
  if (!parsed) throw new SignetVotingError('Invalid election event');

  // Step 1: Verify all ballots, collect valid ones with key images
  const validBallots: Array<{ ballot: NostrEvent; keyImage: string }> = [];
  let invalidCount = 0;

  for (const ballot of ballots) {
    const result = verifyBallot(ballot, election, eligibleRing);
    if (result.valid) {
      const keyImage = getTagValue(ballot, 'key-image')!;
      validBallots.push({ ballot, keyImage });
    } else {
      invalidCount++;
    }
  }

  // Step 2: Deduplicate by key image
  const deduped = new Map<string, NostrEvent>();

  for (const { ballot, keyImage } of validBallots) {
    const existing = deduped.get(keyImage);
    if (existing) {
      if (parsed.reVote === 'allowed') {
        // Keep ballot with latest created_at
        if (ballot.created_at > existing.created_at) {
          deduped.set(keyImage, ballot);
        }
      } else {
        // reVote === 'denied': keep first, reject duplicates
        invalidCount++;
      }
    } else {
      deduped.set(keyImage, ballot);
    }
  }

  // Step 3: Decrypt each ballot's encrypted-vote and count votes
  const voteCounts = new Map<string, number>();
  for (const option of parsed.options) {
    voteCounts.set(option, 0);
  }

  for (const ballot of deduped.values()) {
    const encryptedVote = getTagValue(ballot, 'encrypted-vote');
    if (!encryptedVote) {
      invalidCount++;
      continue;
    }

    try {
      const decrypted = await decryptBallotContent(encryptedVote, tallyPrivateKey);
      if (decrypted.length > 4096) {
        invalidCount++;
        continue;
      }
      const raw = JSON.parse(decrypted);
      if (!raw || typeof raw !== 'object' || typeof raw.option !== 'string') {
        invalidCount++;
        continue;
      }
      const vote = raw as { option: string };
      const current = voteCounts.get(vote.option);
      if (current !== undefined) {
        voteCounts.set(vote.option, current + 1);
      } else {
        invalidCount++;
      }
    } catch {
      invalidCount++;
    }
  }

  // Step 4: Build kind 30484 result event
  const tallyPubkey = getPublicKey(tallyPrivateKey);
  const totalBallots = deduped.size;

  const tags: string[][] = [
    ['d', `${parsed.electionId}:result`],
    ['election', election.id],
    ['total-ballots', String(totalBallots)],
    ['total-eligible', String(eligibleRing.length)],
    ['total-invalid', String(invalidCount)],
  ];

  for (const [option, count] of voteCounts) {
    tags.push(['result', option, String(count)]);
  }

  tags.push(
    ['algo', DEFAULT_CRYPTO_ALGORITHM],
    ['L', SIGNET_LABEL],
    ['l', SIGNET_LABEL],
  );

  const unsigned: UnsignedEvent = {
    kind: SIGNET_KINDS.ELECTION_RESULT,
    pubkey: tallyPubkey,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: '',
  };

  return signEvent(unsigned, tallyPrivateKey);
}

// ── Validation ───────────────────────────────────────────────────────────────

export function validateElection(event: NostrEvent): ValidationResult {
  const errors: string[] = [];
  validateFieldSizeBounds(event, errors);
  if (event.kind !== SIGNET_KINDS.ELECTION) {
    errors.push(`Expected kind ${SIGNET_KINDS.ELECTION}, got ${event.kind}`);
  }
  if (!event.tags.some(t => t[0] === 'L' && t[1] === SIGNET_LABEL)) {
    errors.push('Missing signet protocol label (["L", "signet"])');
  }
  if (!getTagValue(event, 'd')) errors.push('Missing "d" tag (election ID)');
  if (!getTagValue(event, 'title')) errors.push('Missing "title" tag');
  if (!getTagValue(event, 'scale')) errors.push('Missing "scale" tag');
  if (!getTagValue(event, 'opens')) errors.push('Missing "opens" tag');
  if (!getTagValue(event, 'closes')) errors.push('Missing "closes" tag');
  if (!getTagValue(event, 're-vote')) errors.push('Missing "re-vote" tag');
  const options = event.tags.filter(t => t[0] === 'option').map(t => t[1]);
  if (options.length < 2) errors.push('Election must have at least 2 "option" tags');
  const tallyPubkeys = event.tags.filter(t => t[0] === 'tally-pubkey').map(t => t[1]);
  if (tallyPubkeys.length < 1) errors.push('Election must have at least 1 "tally-pubkey" tag');
  return { valid: errors.length === 0, errors };
}

export function validateBallot(event: NostrEvent): ValidationResult {
  const errors: string[] = [];
  validateFieldSizeBounds(event, errors);
  if (event.kind !== SIGNET_KINDS.BALLOT) {
    errors.push(`Expected kind ${SIGNET_KINDS.BALLOT}, got ${event.kind}`);
  }
  if (!event.tags.some(t => t[0] === 'L' && t[1] === SIGNET_LABEL)) {
    errors.push('Missing signet protocol label (["L", "signet"])');
  }
  if (!getTagValue(event, 'd')) errors.push('Missing "d" tag');
  if (!getTagValue(event, 'election')) errors.push('Missing "election" tag');
  if (!getTagValue(event, 'key-image')) errors.push('Missing "key-image" tag');
  if (!getTagValue(event, 'ring-sig')) errors.push('Missing "ring-sig" tag');
  if (!getTagValue(event, 'encrypted-vote')) errors.push('Missing "encrypted-vote" tag');
  return { valid: errors.length === 0, errors };
}

export function validateElectionResult(event: NostrEvent): ValidationResult {
  const errors: string[] = [];
  validateFieldSizeBounds(event, errors);
  if (event.kind !== SIGNET_KINDS.ELECTION_RESULT) {
    errors.push(`Expected kind ${SIGNET_KINDS.ELECTION_RESULT}, got ${event.kind}`);
  }
  if (!event.tags.some(t => t[0] === 'L' && t[1] === SIGNET_LABEL)) {
    errors.push('Missing signet protocol label (["L", "signet"])');
  }
  if (!getTagValue(event, 'd')) errors.push('Missing "d" tag');
  if (!getTagValue(event, 'election')) errors.push('Missing "election" tag');
  if (!getTagValue(event, 'total-ballots')) errors.push('Missing "total-ballots" tag');
  if (!getTagValue(event, 'total-eligible')) errors.push('Missing "total-eligible" tag');
  const results = event.tags.filter(t => t[0] === 'result');
  if (results.length === 0) errors.push('Missing "result" tags');
  return { valid: errors.length === 0, errors };
}
