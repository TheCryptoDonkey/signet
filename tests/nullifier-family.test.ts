import { describe, it, expect } from 'vitest';
import {
  computeNullifier,
  computeNullifierFamily,
  buildNullifierFamilyTags,
  checkNullifierFamilyDuplicate,
  generateKeyPair,
  createSelfDeclaredCredential,
  createProfessionalCredential,
} from '../src/index.js';
import type { DocumentDescriptor, NullifierFamily } from '../src/credentials.js';
import type { NostrEvent } from '../src/types.js';

describe('multi-document nullifier families', () => {
  const passportDoc: DocumentDescriptor = {
    documentType: 'passport',
    countryCode: 'GB',
    documentNumber: '123456789',
  };

  const licenceDoc: DocumentDescriptor = {
    documentType: 'driving_licence',
    countryCode: 'GB',
    documentNumber: 'SMITH901150J99XX',
  };

  const nationalIdDoc: DocumentDescriptor = {
    documentType: 'national_id',
    countryCode: 'GB',
    documentNumber: 'AB123456C',
  };

  describe('computeNullifierFamily', () => {
    it('creates a family from a single document', () => {
      const family = computeNullifierFamily([passportDoc]);
      expect(family.primary).toBeTruthy();
      expect(family.nullifiers).toHaveLength(1);
      expect(family.nullifiers[0].documentType).toBe('passport');
      expect(family.nullifiers[0].nullifier).toBe(family.primary);
    });

    it('creates a family from multiple documents', () => {
      const family = computeNullifierFamily([passportDoc, licenceDoc, nationalIdDoc]);
      expect(family.primary).toBeTruthy();
      expect(family.nullifiers).toHaveLength(3);
      expect(family.nullifiers[0].documentType).toBe('passport');
      expect(family.nullifiers[1].documentType).toBe('driving_licence');
      expect(family.nullifiers[2].documentType).toBe('national_id');
    });

    it('primary nullifier matches computeNullifier for first document', () => {
      const family = computeNullifierFamily([passportDoc, licenceDoc]);
      const expected = computeNullifier('passport', 'GB', '123456789');
      expect(family.primary).toBe(expected);
    });

    it('each document produces a unique nullifier', () => {
      const family = computeNullifierFamily([passportDoc, licenceDoc, nationalIdDoc]);
      const nullifiers = family.nullifiers.map(n => n.nullifier);
      const unique = new Set(nullifiers);
      expect(unique.size).toBe(3);
    });

    it('throws for empty document array', () => {
      expect(() => computeNullifierFamily([])).toThrow('At least one document is required');
    });

    it('produces deterministic results', () => {
      const family1 = computeNullifierFamily([passportDoc, licenceDoc]);
      const family2 = computeNullifierFamily([passportDoc, licenceDoc]);
      expect(family1.primary).toBe(family2.primary);
      expect(family1.nullifiers[1].nullifier).toBe(family2.nullifiers[1].nullifier);
    });
  });

  describe('buildNullifierFamilyTags', () => {
    it('creates correct tags for a family', () => {
      const family = computeNullifierFamily([passportDoc, licenceDoc]);
      const tags = buildNullifierFamilyTags(family);

      // First tag should be the primary nullifier
      expect(tags[0]).toEqual(['nullifier', family.primary]);

      // Additional tags for each document in the family
      expect(tags.length).toBe(3); // 1 nullifier + 2 nullifier-family
      expect(tags[1][0]).toBe('nullifier-family');
      expect(tags[1][1]).toBe(family.nullifiers[0].nullifier);
      expect(tags[1][2]).toBe('passport');
      expect(tags[2][0]).toBe('nullifier-family');
      expect(tags[2][1]).toBe(family.nullifiers[1].nullifier);
      expect(tags[2][2]).toBe('driving_licence');
    });

    it('single document produces nullifier + one nullifier-family tag', () => {
      const family = computeNullifierFamily([passportDoc]);
      const tags = buildNullifierFamilyTags(family);
      expect(tags).toHaveLength(2); // nullifier + nullifier-family
      expect(tags[0][0]).toBe('nullifier');
      expect(tags[1][0]).toBe('nullifier-family');
    });
  });

  describe('checkNullifierFamilyDuplicate', () => {
    it('detects no duplicate when no existing credentials', () => {
      const family = computeNullifierFamily([passportDoc, licenceDoc]);
      const result = checkNullifierFamilyDuplicate(family, []);
      expect(result.isDuplicate).toBe(false);
    });

    it('detects duplicate when primary nullifier matches', async () => {
      // Create a credential with the passport nullifier
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const existingCred = await createProfessionalCredential(
        verifier.privateKey,
        subject.publicKey,
        { assertionEventId: tier1.id, profession: 'legal', jurisdiction: 'GB' }
      );
      // Manually add nullifier tag
      const nullifier = computeNullifier('passport', 'GB', '123456789');
      (existingCred as any).tags.push(['nullifier', nullifier]);

      const family = computeNullifierFamily([passportDoc]);
      const result = checkNullifierFamilyDuplicate(family, [existingCred]);
      expect(result.isDuplicate).toBe(true);
      expect(result.conflicting).toBe(existingCred);
      expect(result.matchedNullifier).toBe(nullifier);
    });

    it('detects duplicate via secondary document in family', async () => {
      // Create a credential with only the licence nullifier
      const verifier = generateKeyPair();
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      const existingCred = await createProfessionalCredential(
        verifier.privateKey,
        subject.publicKey,
        { assertionEventId: tier1.id, profession: 'legal', jurisdiction: 'GB' }
      );
      const licenceNullifier = computeNullifier('driving_licence', 'GB', 'SMITH901150J99XX');
      (existingCred as any).tags.push(['nullifier-family', licenceNullifier, 'driving_licence']);

      // New family uses passport + licence
      const family = computeNullifierFamily([passportDoc, licenceDoc]);
      const result = checkNullifierFamilyDuplicate(family, [existingCred]);
      expect(result.isDuplicate).toBe(true);
      expect(result.matchedNullifier).toBe(licenceNullifier);
    });

    it('cross-document detection catches same person with different primary docs', async () => {
      // Person A verified with passport
      const verifier = generateKeyPair();
      const subjectA = generateKeyPair();
      const tier1A = await createSelfDeclaredCredential(subjectA.privateKey);
      const credA = await createProfessionalCredential(
        verifier.privateKey,
        subjectA.publicKey,
        { assertionEventId: tier1A.id, profession: 'legal', jurisdiction: 'GB' }
      );
      const familyA = computeNullifierFamily([passportDoc, licenceDoc]);
      const tagsA = buildNullifierFamilyTags(familyA);
      for (const tag of tagsA) {
        (credA as any).tags.push(tag);
      }

      // Same person tries to verify with national ID + licence (different primary)
      const familyB = computeNullifierFamily([nationalIdDoc, licenceDoc]);
      const result = checkNullifierFamilyDuplicate(familyB, [credA]);

      // Should detect duplicate via the shared driving licence nullifier
      expect(result.isDuplicate).toBe(true);
    });

    it('no false positive for different people', async () => {
      const verifier = generateKeyPair();
      const subjectA = generateKeyPair();
      const tier1A = await createSelfDeclaredCredential(subjectA.privateKey);
      const credA = await createProfessionalCredential(
        verifier.privateKey,
        subjectA.publicKey,
        { assertionEventId: tier1A.id, profession: 'legal', jurisdiction: 'GB' }
      );
      const passportA: DocumentDescriptor = {
        documentType: 'passport',
        countryCode: 'GB',
        documentNumber: 'AAAA11111',
      };
      const familyA = computeNullifierFamily([passportA]);
      const tagsA = buildNullifierFamilyTags(familyA);
      for (const tag of tagsA) {
        (credA as any).tags.push(tag);
      }

      // Different person with different documents
      const passportB: DocumentDescriptor = {
        documentType: 'passport',
        countryCode: 'GB',
        documentNumber: 'BBBB22222',
      };
      const familyB = computeNullifierFamily([passportB]);
      const result = checkNullifierFamilyDuplicate(familyB, [credA]);
      expect(result.isDuplicate).toBe(false);
    });
  });
});
