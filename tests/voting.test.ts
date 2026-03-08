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
      };
      expect(parsed.tallierPubkey).toBe('tallier-key');
    });
  });
});
