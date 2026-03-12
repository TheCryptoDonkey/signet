import { describe, it, expect } from 'vitest';
import { SIGNET_KINDS, ENTITY_LABELS } from '../src/constants.js';
import type {
  ElectionScale,
  ReVotePolicy,
  ElectionParams,
  ParsedElection,
  BallotParams,
  ParsedBallot,
  ElectionResultParams,
  ParsedElectionResult,
} from '../src/types.js';
import {
  createElection, parseElection, castBallot, verifyBallot, tallyElection,
  encryptBallotContent, decryptBallotContent,
  validateElection, validateBallot, validateElectionResult,
} from '../src/voting.js';
import { computeKeyImage } from '../src/lsag.js';
import { generateKeyPair } from '../src/crypto.js';

describe('voting extension', () => {
  describe('event kind constants', () => {
    it('ELECTION is 30482', () => {
      expect(SIGNET_KINDS.ELECTION).toBe(30482);
    });

    it('BALLOT is 30483', () => {
      expect(SIGNET_KINDS.BALLOT).toBe(30483);
    });

    it('ELECTION_RESULT is 30484', () => {
      expect(SIGNET_KINDS.ELECTION_RESULT).toBe(30484);
    });

    it('all kind numbers are unique', () => {
      const values = Object.values(SIGNET_KINDS);
      const unique = new Set(values);
      expect(unique.size).toBe(values.length);
    });

    it('has 11 total event kinds (30470-30484, gap at 30478-30481)', () => {
      expect(Object.keys(SIGNET_KINDS)).toHaveLength(11);
    });
  });

  describe('type compilation checks', () => {
    it('ElectionScale accepts valid values', () => {
      const scales: ElectionScale[] = ['organisational', 'community', 'national'];
      expect(scales).toHaveLength(3);
    });

    it('ReVotePolicy accepts valid values', () => {
      const policies: ReVotePolicy[] = ['allowed', 'denied'];
      expect(policies).toHaveLength(2);
    });

    it('ElectionParams compiles with correct structure', () => {
      const params: ElectionParams = {
        electionId: 'test-election-1',
        title: 'Test Election',
        options: ['Option A', 'Option B'],
        scale: 'community',
        eligibleEntityTypes: ['natural_person', 'persona'],
        eligibleMinTier: 2,
        opens: Math.floor(Date.now() / 1000) + 3600,
        closes: Math.floor(Date.now() / 1000) + 86400,
        reVote: 'allowed',
        tallyPubkeys: ['abc123'],
      };
      expect(params.electionId).toBe('test-election-1');
      expect(params.options).toHaveLength(2);
      expect(params.scale).toBe('community');
    });

    it('BallotParams compiles with correct structure', () => {
      const params: BallotParams = {
        electionId: 'test-election-1',
        electionEventId: 'event-abc',
        keyImage: 'deadbeef',
        ringSig: 'cafebabe',
        encryptedVote: 'encrypted-content',
      };
      expect(params.electionId).toBe('test-election-1');
      expect(params.keyImage).toBe('deadbeef');
    });

    it('ElectionResultParams compiles with correct structure', () => {
      const params: ElectionResultParams = {
        electionId: 'test-election-1',
        electionEventId: 'event-abc',
        results: [
          { option: 'Option A', count: 42 },
          { option: 'Option B', count: 58 },
        ],
        totalBallots: 100,
        totalEligible: 150,
      };
      expect(params.results).toHaveLength(2);
      expect(params.totalBallots).toBe(100);
    });

    it('ParsedElection includes authorityPubkey', () => {
      const parsed: ParsedElection = {
        electionId: 'test',
        title: 'Test',
        options: ['A', 'B'],
        scale: 'organisational',
        eligibleEntityTypes: ['natural_person'],
        eligibleMinTier: 1,
        opens: 0,
        closes: 1,
        reVote: 'denied',
        tallyPubkeys: ['key1'],
        authorityPubkey: 'authority-key',
        algorithm: 'secp256k1',
      };
      expect(parsed.authorityPubkey).toBe('authority-key');
    });

    it('ParsedBallot includes ephemeralPubkey and timestamp', () => {
      const parsed: ParsedBallot = {
        electionId: 'test',
        electionEventId: 'event',
        keyImage: 'img',
        ringSig: 'sig',
        encryptedVote: 'vote',
        ephemeralPubkey: 'ephemeral-key',
        timestamp: 1234567890,
        algorithm: 'secp256k1',
      };
      expect(parsed.ephemeralPubkey).toBe('ephemeral-key');
      expect(parsed.timestamp).toBe(1234567890);
    });

    it('ParsedElectionResult includes tallierPubkey', () => {
      const parsed: ParsedElectionResult = {
        electionId: 'test',
        electionEventId: 'event',
        results: [{ option: 'A', count: 10 }],
        totalBallots: 10,
        totalEligible: 20,
        totalInvalid: 0,
        tallierPubkey: 'tallier-key',
        algorithm: 'secp256k1',
      };
      expect(parsed.tallierPubkey).toBe('tallier-key');
    });
  });
});

// Helper to build a standard election params object with configurable time window
function makeElectionParams(overrides: Partial<ElectionParams> = {}): ElectionParams {
  const now = Math.floor(Date.now() / 1000);
  return {
    electionId: 'test-election',
    title: 'Test Election',
    options: ['Option A', 'Option B', 'Option C'],
    scale: 'community',
    eligibleEntityTypes: ['natural_person'],
    eligibleMinTier: 1,
    opens: now - 3600,     // opened 1 hour ago
    closes: now + 3600,    // closes in 1 hour
    reVote: 'allowed',
    tallyPubkeys: [],      // filled in per test
    ...overrides,
  };
}

describe('voting protocol', () => {
  // Generate keys used across tests
  const authority = generateKeyPair();
  const tally = generateKeyPair();
  const voter1 = generateKeyPair();
  const voter2 = generateKeyPair();
  const voter3 = generateKeyPair();

  // Ring of eligible voters (minimum 2 for LSAG)
  const eligibleRing = [voter1.publicKey, voter2.publicKey, voter3.publicKey];

  describe('createElection', () => {
    it('creates a valid kind 30482 event', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const event = await createElection(authority.privateKey, params);

      expect(event.kind).toBe(SIGNET_KINDS.ELECTION);
      expect(event.id).toBeDefined();
      expect(event.sig).toBeDefined();
      expect(event.pubkey).toBe(authority.publicKey);
    });

    it('includes all required tags', async () => {
      const params = makeElectionParams({
        tallyPubkeys: [tally.publicKey],
        description: 'A test election',
        tallyThreshold: [2, 3],
        ringSize: 5,
        eligibleCommunity: 'test-community',
      });
      const event = await createElection(authority.privateKey, params);

      const tagMap = new Map<string, string[]>();
      for (const tag of event.tags) {
        if (!tagMap.has(tag[0])) tagMap.set(tag[0], []);
        tagMap.get(tag[0])!.push(tag[1]);
      }

      expect(tagMap.get('d')).toEqual([params.electionId]);
      expect(tagMap.get('title')).toEqual([params.title]);
      expect(tagMap.get('scale')).toEqual(['community']);
      expect(tagMap.get('opens')).toEqual([String(params.opens)]);
      expect(tagMap.get('closes')).toEqual([String(params.closes)]);
      expect(tagMap.get('re-vote')).toEqual(['allowed']);
      expect(tagMap.get('algo')).toEqual(['secp256k1']);
      expect(tagMap.get('L')).toEqual(['signet']);
      expect(tagMap.get('l')).toEqual(['signet']);
      expect(tagMap.get('description')).toEqual(['A test election']);
      expect(tagMap.get('option')).toEqual(['Option A', 'Option B', 'Option C']);
      expect(tagMap.get('tally-pubkey')).toEqual([tally.publicKey]);
      expect(tagMap.get('tally-threshold')).toEqual(['2/3']);
      expect(tagMap.get('ring-size')).toEqual(['5']);
      expect(tagMap.get('eligible-community')).toEqual(['test-community']);
    });

    it('rejects fewer than 2 options', async () => {
      const params = makeElectionParams({
        options: ['Only one'],
        tallyPubkeys: [tally.publicKey],
      });
      await expect(createElection(authority.privateKey, params)).rejects.toThrow('at least 2 options');
    });

    it('rejects closes <= opens', async () => {
      const now = Math.floor(Date.now() / 1000);
      const params = makeElectionParams({
        opens: now + 100,
        closes: now + 100,
        tallyPubkeys: [tally.publicKey],
      });
      await expect(createElection(authority.privateKey, params)).rejects.toThrow('closing time must be after opening');
    });

    it('rejects empty tally pubkeys', async () => {
      const params = makeElectionParams({ tallyPubkeys: [] });
      await expect(createElection(authority.privateKey, params)).rejects.toThrow('at least 1 tally pubkey');
    });
  });

  describe('parseElection', () => {
    it('round-trips create and parse', async () => {
      const params = makeElectionParams({
        tallyPubkeys: [tally.publicKey],
        description: 'Round-trip test',
      });
      const event = await createElection(authority.privateKey, params);
      const parsed = parseElection(event);

      expect(parsed).not.toBeNull();
      expect(parsed!.electionId).toBe(params.electionId);
      expect(parsed!.title).toBe(params.title);
      expect(parsed!.options).toEqual(params.options);
      expect(parsed!.scale).toBe(params.scale);
      expect(parsed!.opens).toBe(params.opens);
      expect(parsed!.closes).toBe(params.closes);
      expect(parsed!.reVote).toBe(params.reVote);
      expect(parsed!.tallyPubkeys).toEqual([tally.publicKey]);
      expect(parsed!.authorityPubkey).toBe(authority.publicKey);
      expect(parsed!.algorithm).toBe('secp256k1');
      expect(parsed!.description).toBe('Round-trip test');
    });

    it('returns null for wrong kind', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const event = await createElection(authority.privateKey, params);
      const fakeEvent = { ...event, kind: 30470 };
      expect(parseElection(fakeEvent)).toBeNull();
    });
  });

  describe('ballot encryption', () => {
    it('round-trips encrypted content', async () => {
      const plaintext = JSON.stringify({ option: 'Option A' });
      const encrypted = await encryptBallotContent(plaintext, tally.publicKey);
      const decrypted = await decryptBallotContent(encrypted, tally.privateKey);
      expect(decrypted).toBe(plaintext);
    });

    it('different encryptions produce different ciphertext', async () => {
      const plaintext = 'same message';
      const enc1 = await encryptBallotContent(plaintext, tally.publicKey);
      const enc2 = await encryptBallotContent(plaintext, tally.publicKey);
      // Ephemeral keys and nonces differ, so ciphertext should differ
      expect(enc1).not.toBe(enc2);
    });
  });

  describe('castBallot and verifyBallot', () => {
    it('casts a valid ballot with correct kind and key-image tag', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const election = await createElection(authority.privateKey, params);

      const { event, ephemeralPubkey } = await castBallot(
        voter1.privateKey, election, 'Option A', eligibleRing,
      );

      expect(event.kind).toBe(SIGNET_KINDS.BALLOT);
      expect(event.pubkey).toBe(ephemeralPubkey);

      // Key image tag should be present
      const keyImageTag = event.tags.find((t) => t[0] === 'key-image');
      expect(keyImageTag).toBeDefined();
      expect(keyImageTag![1]).toHaveLength(66); // compressed point hex
    });

    it('verifies a valid ballot', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const election = await createElection(authority.privateKey, params);

      const { event } = await castBallot(
        voter1.privateKey, election, 'Option B', eligibleRing,
      );

      const result = verifyBallot(event, election, eligibleRing);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('does not leak vote content in ring signature (C1 fix)', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const election = await createElection(authority.privateKey, params);

      const selectedOption = 'Option A';
      const { event } = await castBallot(
        voter1.privateKey, election, selectedOption, eligibleRing,
      );

      // The ring-sig tag contains the LSAG signature as JSON
      const ringSigTag = event.tags.find((t) => t[0] === 'ring-sig');
      expect(ringSigTag).toBeDefined();
      const ringSigJson = ringSigTag![1];

      // The plaintext vote MUST NOT appear in the ring signature
      expect(ringSigJson).not.toContain(selectedOption);

      // The message field should be a hash commitment, not the plaintext
      const parsed = JSON.parse(ringSigJson);
      expect(parsed.message).not.toContain(selectedOption);
      expect(parsed.message).toMatch(/^[^:]+:[0-9a-f]{64}$/); // electionId:sha256hex
    });

    it('rejects ballot with tampered encrypted-vote (binding check)', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const election = await createElection(authority.privateKey, params);

      const { event } = await castBallot(
        voter1.privateKey, election, 'Option A', eligibleRing,
      );

      // Tamper with the encrypted vote tag
      const tampered = {
        ...event,
        tags: event.tags.map(t =>
          t[0] === 'encrypted-vote' ? ['encrypted-vote', 'deadbeef'.repeat(20)] : t,
        ),
      };

      const result = verifyBallot(tampered, election, eligibleRing);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Ring signature message does not match encrypted vote commitment');
    });

    it('rejects voter not in ring', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const election = await createElection(authority.privateKey, params);
      const outsider = generateKeyPair();

      await expect(
        castBallot(outsider.privateKey, election, 'Option A', eligibleRing),
      ).rejects.toThrow('not found in eligible ring');
    });

    it('rejects invalid option', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const election = await createElection(authority.privateKey, params);

      await expect(
        castBallot(voter1.privateKey, election, 'Nonexistent Option', eligibleRing),
      ).rejects.toThrow('not valid for this election');
    });

    it('rejects not-yet-open election', async () => {
      const now = Math.floor(Date.now() / 1000);
      const params = makeElectionParams({
        opens: now + 7200,
        closes: now + 86400,
        tallyPubkeys: [tally.publicKey],
      });
      const election = await createElection(authority.privateKey, params);

      await expect(
        castBallot(voter1.privateKey, election, 'Option A', eligibleRing),
      ).rejects.toThrow('not yet opened');
    });

    it('rejects already-closed election', async () => {
      const now = Math.floor(Date.now() / 1000);
      const params = makeElectionParams({
        opens: now - 86400,
        closes: now - 3600,
        tallyPubkeys: [tally.publicKey],
      });
      const election = await createElection(authority.privateKey, params);

      await expect(
        castBallot(voter1.privateKey, election, 'Option A', eligibleRing),
      ).rejects.toThrow('already closed');
    });
  });

  describe('tallyElection', () => {
    it('tallies multiple ballots correctly', async () => {
      const params = makeElectionParams({ tallyPubkeys: [tally.publicKey] });
      const election = await createElection(authority.privateKey, params);

      const ballot1 = await castBallot(voter1.privateKey, election, 'Option A', eligibleRing);
      const ballot2 = await castBallot(voter2.privateKey, election, 'Option B', eligibleRing);
      const ballot3 = await castBallot(voter3.privateKey, election, 'Option A', eligibleRing);

      const result = await tallyElection(
        [ballot1.event, ballot2.event, ballot3.event],
        election, tally.privateKey, eligibleRing,
      );

      expect(result.kind).toBe(SIGNET_KINDS.ELECTION_RESULT);

      // Check result tags
      const resultTags = result.tags.filter((t) => t[0] === 'result');
      const optionA = resultTags.find((t) => t[1] === 'Option A');
      const optionB = resultTags.find((t) => t[1] === 'Option B');
      const optionC = resultTags.find((t) => t[1] === 'Option C');

      expect(optionA).toBeDefined();
      expect(optionA![2]).toBe('2');
      expect(optionB).toBeDefined();
      expect(optionB![2]).toBe('1');
      expect(optionC).toBeDefined();
      expect(optionC![2]).toBe('0');

      const totalBallots = result.tags.find((t) => t[0] === 'total-ballots');
      expect(totalBallots![1]).toBe('3');
    });

    it('deduplicates by key image (re-vote allowed: latest wins)', async () => {
      const params = makeElectionParams({
        tallyPubkeys: [tally.publicKey],
        reVote: 'allowed',
      });
      const election = await createElection(authority.privateKey, params);

      // voter1 votes twice for different options
      const ballot1a = await castBallot(voter1.privateKey, election, 'Option A', eligibleRing);
      const ballot1b = await castBallot(voter1.privateKey, election, 'Option B', eligibleRing);
      // Ensure ballot1b is later
      (ballot1b.event as any).created_at = ballot1a.event.created_at + 1;

      const ballot2 = await castBallot(voter2.privateKey, election, 'Option A', eligibleRing);

      const result = await tallyElection(
        [ballot1a.event, ballot1b.event, ballot2.event],
        election, tally.privateKey, eligibleRing,
      );

      const totalBallots = result.tags.find((t) => t[0] === 'total-ballots');
      expect(totalBallots![1]).toBe('2'); // deduplicated: voter1 counted once

      // voter1's latest vote was Option B
      const resultTags = result.tags.filter((t) => t[0] === 'result');
      const optionA = resultTags.find((t) => t[1] === 'Option A');
      const optionB = resultTags.find((t) => t[1] === 'Option B');
      expect(optionA![2]).toBe('1'); // only voter2
      expect(optionB![2]).toBe('1'); // voter1's latest
    });

    it('rejects duplicate key images when re-vote denied', async () => {
      const params = makeElectionParams({
        tallyPubkeys: [tally.publicKey],
        reVote: 'denied',
      });
      const election = await createElection(authority.privateKey, params);

      const ballot1a = await castBallot(voter1.privateKey, election, 'Option A', eligibleRing);
      const ballot1b = await castBallot(voter1.privateKey, election, 'Option B', eligibleRing);
      const ballot2 = await castBallot(voter2.privateKey, election, 'Option A', eligibleRing);

      const result = await tallyElection(
        [ballot1a.event, ballot1b.event, ballot2.event],
        election, tally.privateKey, eligibleRing,
      );

      const totalBallots = result.tags.find((t) => t[0] === 'total-ballots');
      expect(totalBallots![1]).toBe('2'); // first from voter1 kept, duplicate rejected

      const totalInvalid = result.tags.find((t) => t[0] === 'total-invalid');
      expect(parseInt(totalInvalid![1], 10)).toBeGreaterThanOrEqual(1);

      // voter1's first vote was Option A
      const resultTags = result.tags.filter((t) => t[0] === 'result');
      const optionA = resultTags.find((t) => t[1] === 'Option A');
      expect(optionA![2]).toBe('2'); // voter1 first + voter2
    });
  });
});

describe('security hardening', () => {
  it('verifyBallot handles malformed ring-sig JSON gracefully', () => {
    const ballot = {
      kind: SIGNET_KINDS.BALLOT, id: 'x', sig: 'y', pubkey: 'a'.repeat(64),
      created_at: Math.floor(Date.now() / 1000),
      content: '',
      tags: [
        ['L', 'signet'], ['d', 'test'], ['election', 'abc'],
        ['key-image', 'ki'], ['ring-sig', 'not-json'], ['encrypted-vote', 'enc'],
      ],
    } as any;
    const election = {
      kind: SIGNET_KINDS.ELECTION, id: 'abc', sig: 'z', pubkey: 'b'.repeat(64),
      created_at: 0, content: '',
      tags: [
        ['L', 'signet'], ['d', 'eid'], ['title', 'T'], ['scale', 'organisational'],
        ['opens', '0'], ['closes', '99999999999'], ['re-vote', 'allowed'],
        ['option', 'A'], ['option', 'B'], ['tally-pubkey', 'c'.repeat(64)],
      ],
    } as any;
    const result = verifyBallot(ballot, election, ['a'.repeat(64)]);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Invalid ring-sig JSON');
  });

  it('verifyBallot handles structurally invalid ring-sig', () => {
    const ballot = {
      kind: SIGNET_KINDS.BALLOT, id: 'x', sig: 'y', pubkey: 'a'.repeat(64),
      created_at: Math.floor(Date.now() / 1000),
      content: '',
      tags: [
        ['L', 'signet'], ['d', 'test'], ['election', 'abc'],
        ['key-image', 'ki'], ['ring-sig', JSON.stringify({ wrong: true })], ['encrypted-vote', 'enc'],
      ],
    } as any;
    const election = {
      kind: SIGNET_KINDS.ELECTION, id: 'abc', sig: 'z', pubkey: 'b'.repeat(64),
      created_at: 0, content: '',
      tags: [
        ['L', 'signet'], ['d', 'eid'], ['title', 'T'], ['scale', 'organisational'],
        ['opens', '0'], ['closes', '99999999999'], ['re-vote', 'allowed'],
        ['option', 'A'], ['option', 'B'], ['tally-pubkey', 'c'.repeat(64)],
      ],
    } as any;
    const result = verifyBallot(ballot, election, ['a'.repeat(64)]);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('Invalid ring-sig structure');
  });

  it('validateElection enforces field-size bounds', () => {
    const oversizedContent = 'x'.repeat(70000);
    const event = {
      kind: SIGNET_KINDS.ELECTION, id: 'x', sig: 'y', pubkey: 'a'.repeat(64),
      created_at: 0, content: oversizedContent,
      tags: [['L', 'signet']],
    } as any;
    const result = validateElection(event);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('maximum length'))).toBe(true);
  });

  it('validateBallot enforces field-size bounds', () => {
    const event = {
      kind: SIGNET_KINDS.BALLOT, id: 'x', sig: 'y', pubkey: 'a'.repeat(64),
      created_at: 0, content: '',
      tags: Array.from({ length: 110 }, (_, i) => ['tag' + i, 'v']),
    } as any;
    const result = validateBallot(event);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('too many tags'))).toBe(true);
  });
});

describe('structural validation', () => {
  const authority = generateKeyPair();
  const tally = generateKeyPair();
  const validParams: ElectionParams = {
    electionId: 'validate-test',
    title: 'Validation Test',
    options: ['Yes', 'No'],
    scale: 'organisational',
    eligibleEntityTypes: ['natural_person'],
    eligibleMinTier: 1,
    opens: Math.floor(Date.now() / 1000) - 3600,
    closes: Math.floor(Date.now() / 1000) + 86400,
    reVote: 'allowed',
    tallyPubkeys: [tally.publicKey],
  };

  it('validates a well-formed election event', async () => {
    const event = await createElection(authority.privateKey, validParams);
    const result = validateElection(event);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('rejects election with wrong kind', () => {
    const bad = { kind: 30470, tags: [['L', 'signet']], pubkey: 'a'.repeat(64), content: '', id: 'x', sig: 'y', created_at: 0 } as any;
    const result = validateElection(bad);
    expect(result.valid).toBe(false);
  });

  it('rejects election missing required tags', () => {
    const bad = { kind: 30482, tags: [['L', 'signet']], pubkey: 'a'.repeat(64), content: '', id: 'x', sig: 'y', created_at: 0 } as any;
    const result = validateElection(bad);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('validates a well-formed ballot event', async () => {
    const auth = generateKeyPair();
    const tallyKp = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const electionEvent = await createElection(auth.privateKey, {
      electionId: 'val-test', title: 'Val Test', options: ['A', 'B'],
      scale: 'organisational', eligibleEntityTypes: ['natural_person'],
      eligibleMinTier: 1, opens: now - 3600, closes: now + 86400,
      reVote: 'allowed', tallyPubkeys: [tallyKp.publicKey],
    });
    const voter = generateKeyPair();
    const ring = [voter.publicKey, generateKeyPair().publicKey, generateKeyPair().publicKey];
    const { event } = await castBallot(voter.privateKey, electionEvent, 'A', ring);
    expect(validateBallot(event).valid).toBe(true);
  });

  it('validates a well-formed election result event', async () => {
    const auth = generateKeyPair();
    const tallyKp = generateKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const electionEvent = await createElection(auth.privateKey, {
      electionId: 'val-result-test', title: 'Val Result', options: ['X', 'Y'],
      scale: 'organisational', eligibleEntityTypes: ['natural_person'],
      eligibleMinTier: 1, opens: now - 7200, closes: now + 86400,
      reVote: 'allowed', tallyPubkeys: [tallyKp.publicKey],
    });
    const v1 = generateKeyPair();
    const v2 = generateKeyPair();
    const ring = [v1.publicKey, v2.publicKey, generateKeyPair().publicKey];
    const b1 = await castBallot(v1.privateKey, electionEvent, 'X', ring);
    const b2 = await castBallot(v2.privateKey, electionEvent, 'Y', ring);
    const result = await tallyElection([b1.event, b2.event], electionEvent, tallyKp.privateKey, ring);
    expect(validateElectionResult(result).valid).toBe(true);
  });
});

describe('full voting flow integration', () => {
  it('end-to-end: create, cast 3 ballots, tally', async () => {
    const auth = generateKeyPair();
    const tally = generateKeyPair();
    const voters = [generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const ring = voters.map(v => v.publicKey);
    const now = Math.floor(Date.now() / 1000);

    const election = await createElection(auth.privateKey, {
      electionId: 'integration-test',
      title: 'Integration Test Election',
      options: ['Yes', 'No'],
      scale: 'organisational',
      eligibleEntityTypes: ['natural_person'],
      eligibleMinTier: 1,
      opens: now - 3600,
      closes: now + 86400,
      reVote: 'allowed',
      tallyPubkeys: [tally.publicKey],
    });
    expect(election.kind).toBe(30482);

    const b0 = await castBallot(voters[0].privateKey, election, 'Yes', ring);
    const b1 = await castBallot(voters[1].privateKey, election, 'No', ring);
    const b2 = await castBallot(voters[2].privateKey, election, 'Yes', ring);

    for (const ballot of [b0, b1, b2]) {
      const v = verifyBallot(ballot.event, election, ring);
      expect(v.valid).toBe(true);
    }

    // All key images unique
    const keyImages = [b0, b1, b2].map(b =>
      b.event.tags.find(t => t[0] === 'key-image')![1],
    );
    expect(new Set(keyImages).size).toBe(3);

    const result = await tallyElection(
      [b0.event, b1.event, b2.event], election, tally.privateKey, ring,
    );
    expect(result.kind).toBe(30484);
    const yesResult = result.tags.find(t => t[0] === 'result' && t[1] === 'Yes');
    const noResult = result.tags.find(t => t[0] === 'result' && t[1] === 'No');
    expect(yesResult?.[2]).toBe('2');
    expect(noResult?.[2]).toBe('1');
  });
});
