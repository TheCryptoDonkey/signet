import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createPolicy,
  parsePolicy,
  checkPolicyCompliance,
  PolicyChecker,
  verifyEvent,
  getTagValue,
  SIGNET_KINDS,
} from '../src/index.js';

describe('policies', () => {
  it('creates a valid community policy', async () => {
    const operator = generateKeyPair();
    const policy = await createPolicy(operator.privateKey, {
      communityId: 'kids-learning-group',
      adultMinTier: 3,
      childMinTier: 4,
      enforcement: 'both',
      minScore: 50,
      modMinTier: 3,
      verifierBond: 100000,
      revocationThreshold: 5,
      description: 'Safe space for children',
    });

    expect(policy.kind).toBe(SIGNET_KINDS.POLICY);
    expect(getTagValue(policy, 'adult-min-tier')).toBe('3');
    expect(getTagValue(policy, 'child-min-tier')).toBe('4');
    expect(getTagValue(policy, 'enforcement')).toBe('both');
    expect(getTagValue(policy, 'min-score')).toBe('50');
    expect(getTagValue(policy, 'verifier-bond')).toBe('100000');
    expect(policy.content).toBe('Safe space for children');

    const valid = await verifyEvent(policy);
    expect(valid).toBe(true);
  });

  describe('parsePolicy', () => {
    it('parses all policy fields', async () => {
      const operator = generateKeyPair();
      const policy = await createPolicy(operator.privateKey, {
        communityId: 'test-community',
        adultMinTier: 2,
        childMinTier: 3,
        enforcement: 'client',
        minScore: 40,
        modMinTier: 3,
      });

      const parsed = parsePolicy(policy);
      expect(parsed).not.toBeNull();
      expect(parsed!.communityId).toBe('test-community');
      expect(parsed!.adultMinTier).toBe(2);
      expect(parsed!.childMinTier).toBe(3);
      expect(parsed!.enforcement).toBe('client');
      expect(parsed!.minScore).toBe(40);
      expect(parsed!.modMinTier).toBe(3);
    });
  });

  describe('checkPolicyCompliance', () => {
    const policy = {
      communityId: 'test',
      adultMinTier: 2 as const,
      childMinTier: 4 as const,
      enforcement: 'client' as const,
      minScore: 50,
      modMinTier: 3 as const,
    };

    it('allows adults meeting tier and score', () => {
      const result = checkPolicyCompliance(policy, 3, 75);
      expect(result.allowed).toBe(true);
    });

    it('rejects adults below tier', () => {
      const result = checkPolicyCompliance(policy, 1, 90);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Tier 1');
    });

    it('rejects adults below score', () => {
      const result = checkPolicyCompliance(policy, 2, 30);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Score 30');
    });

    it('checks child requirements separately', () => {
      // Tier 3 adult passes adult check but fails child check
      const adultResult = checkPolicyCompliance(policy, 3, 75, { isChild: false });
      expect(adultResult.allowed).toBe(true);

      const childResult = checkPolicyCompliance(policy, 3, 75, { isChild: true });
      expect(childResult.allowed).toBe(false);
      expect(childResult.requiredTier).toBe(4);
    });

    it('checks moderator requirements', () => {
      // Tier 2 passes adult but fails mod
      const modResult = checkPolicyCompliance(policy, 2, 60, { isModerator: true });
      expect(modResult.allowed).toBe(false);
      expect(modResult.requiredTier).toBe(3);
    });
  });

  describe('PolicyChecker', () => {
    it('provides convenience methods', async () => {
      const operator = generateKeyPair();
      const policyEvent = await createPolicy(operator.privateKey, {
        communityId: 'max-safety',
        adultMinTier: 3,
        childMinTier: 4,
        enforcement: 'both',
        minScore: 60,
        modMinTier: 3,
      });

      const checker = new PolicyChecker(policyEvent);

      expect(checker.checkAdult(3, 70).allowed).toBe(true);
      expect(checker.checkAdult(2, 70).allowed).toBe(false);
      expect(checker.checkChild(4, 70).allowed).toBe(true);
      expect(checker.checkChild(3, 70).allowed).toBe(false);
      expect(checker.checkModerator(3, 70).allowed).toBe(true);
      expect(checker.checkModerator(2, 70).allowed).toBe(false);
    });
  });
});
