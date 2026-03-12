import { describe, it, expect } from 'vitest';
import {
  MerkleTree,
  verifyMerkleProof,
  verifySelectiveDisclosure,
} from '../src/index.js';

describe('merkle', () => {
  const attributes = {
    tier: '3',
    type: 'professional',
    scope: 'adult',
    profession: 'solicitor',
    jurisdiction: 'UK',
    method: 'in-person-id',
  };

  describe('MerkleTree', () => {
    it('builds a tree with a deterministic root', () => {
      const tree1 = new MerkleTree(attributes);
      const tree2 = new MerkleTree(attributes);
      expect(tree1.getRoot()).toBe(tree2.getRoot());
      expect(tree1.getRoot()).toHaveLength(64);
    });

    it('produces different roots for different attributes', () => {
      const tree1 = new MerkleTree(attributes);
      const tree2 = new MerkleTree({ ...attributes, tier: '4' });
      expect(tree1.getRoot()).not.toBe(tree2.getRoot());
    });
  });

  describe('selective disclosure', () => {
    it('reveals only selected attributes', () => {
      const tree = new MerkleTree(attributes);
      const disclosure = tree.disclose(['tier', 'jurisdiction']);

      expect(Object.keys(disclosure.revealedAttributes)).toHaveLength(2);
      expect(disclosure.revealedAttributes['tier']).toBe('3');
      expect(disclosure.revealedAttributes['jurisdiction']).toBe('UK');
      expect(disclosure.proofs).toHaveLength(2);
      expect(disclosure.merkleRoot).toBe(tree.getRoot());
    });

    it('does not reveal unselected attributes', () => {
      const tree = new MerkleTree(attributes);
      const disclosure = tree.disclose(['tier']);

      expect(disclosure.revealedAttributes['profession']).toBeUndefined();
      expect(disclosure.revealedAttributes['scope']).toBeUndefined();
    });
  });

  describe('verifyMerkleProof', () => {
    it('verifies a valid proof', () => {
      const tree = new MerkleTree(attributes);
      const proof = tree.prove('profession');
      expect(verifyMerkleProof('profession', 'solicitor', proof)).toBe(true);
    });

    it('rejects proof with wrong value', () => {
      const tree = new MerkleTree(attributes);
      const proof = tree.prove('profession');
      expect(verifyMerkleProof('profession', 'doctor', proof)).toBe(false);
    });

    it('rejects proof with wrong key', () => {
      const tree = new MerkleTree(attributes);
      const proof = tree.prove('profession');
      expect(verifyMerkleProof('tier', 'solicitor', proof)).toBe(false);
    });
  });

  describe('verifySelectiveDisclosure', () => {
    it('verifies a valid disclosure', () => {
      const tree = new MerkleTree(attributes);
      const disclosure = tree.disclose(['tier', 'scope', 'jurisdiction']);
      expect(verifySelectiveDisclosure(disclosure)).toBe(true);
    });

    it('rejects tampered disclosure', () => {
      const tree = new MerkleTree(attributes);
      const disclosure = tree.disclose(['tier']);

      // Tamper
      disclosure.revealedAttributes['tier'] = '4';
      expect(verifySelectiveDisclosure(disclosure)).toBe(false);
    });

    it('verifies single attribute disclosure', () => {
      const tree = new MerkleTree(attributes);
      const disclosure = tree.disclose(['method']);
      expect(verifySelectiveDisclosure(disclosure)).toBe(true);
      expect(disclosure.revealedAttributes['method']).toBe('in-person-id');
    });
  });

  describe('edge cases', () => {
    it('works with a single attribute', () => {
      const tree = new MerkleTree({ only: 'one' });
      const proof = tree.prove('only');
      expect(verifyMerkleProof('only', 'one', proof)).toBe(true);
    });

    it('works with two attributes', () => {
      const tree = new MerkleTree({ a: '1', b: '2' });
      expect(verifyMerkleProof('a', '1', tree.prove('a'))).toBe(true);
      expect(verifyMerkleProof('b', '2', tree.prove('b'))).toBe(true);
    });

    it('works with power-of-2 attributes', () => {
      const attrs = { a: '1', b: '2', c: '3', d: '4' };
      const tree = new MerkleTree(attrs);
      for (const [k, v] of Object.entries(attrs)) {
        expect(verifyMerkleProof(k, v, tree.prove(k))).toBe(true);
      }
    });

    it('throws for non-existent attribute', () => {
      const tree = new MerkleTree(attributes);
      expect(() => tree.prove('nonexistent')).toThrow('not found');
    });
  });

  describe('security — proof position integrity', () => {
    it('proof for index 0 does not verify at index 1 (no sibling transplant)', () => {
      // This test verifies that the Merkle tree uses positional ordering
      // (left vs right child) rather than sorted ordering, preventing
      // a proof generated for one leaf from being valid for its sibling.
      const attrs = { a: '1', b: '2', c: '3', d: '4' };
      const tree = new MerkleTree(attrs);

      const proofA = tree.prove('a');
      const proofB = tree.prove('b');

      // Each proof should only verify for its own key-value pair
      expect(verifyMerkleProof('a', '1', proofA)).toBe(true);
      expect(verifyMerkleProof('b', '2', proofB)).toBe(true);

      // Swapping index should fail — proof is position-bound
      const transplanted = { ...proofA, index: proofB.index };
      expect(verifyMerkleProof('a', '1', transplanted)).toBe(false);
    });

    it('proof siblings differ based on position in the tree', () => {
      const attrs = { a: '1', b: '2', c: '3', d: '4' };
      const tree = new MerkleTree(attrs);

      // Sorted entries: a, b, c, d (indices 0, 1, 2, 3)
      const proofA = tree.prove('a'); // index 0
      const proofB = tree.prove('b'); // index 1

      // Index 0 and 1 are siblings, so first sibling should be the other's leaf hash
      expect(proofA.index).toBe(0);
      expect(proofB.index).toBe(1);
      // They share a sibling at level 0 but are different positions
      expect(proofA.siblings[0]).toBe(proofB.leaf);
      expect(proofB.siblings[0]).toBe(proofA.leaf);
    });
  });
});
