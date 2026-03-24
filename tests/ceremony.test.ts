// Tests for two-credential ceremony, credential chains, guardian delegation, nullifiers

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createTwoCredentialCeremony,
  supersedeCredential,
  resolveCredentialChain,
  isSuperseded,
  computeNullifier,
  checkNullifierDuplicate,
  buildNullifierChainTag,
  createGuardianDelegation,
  parseCredential,
  verifyCredential,
  verifyMerkleProof,
  getTagValue,
  getTagValues,
  ATTESTATION_KIND,
  ATTESTATION_TYPES,
} from '../src/index.js';

describe('Two-Credential Ceremony', () => {
  const verifier = generateKeyPair();
  const naturalPerson = generateKeyPair();
  const persona = generateKeyPair();

  const baseOpts = {
    name: 'Alice Smith',
    nationality: 'GB',
    documentType: 'passport',
    documentNumber: 'AB123456',
    documentCountry: 'GB',
    dateOfBirth: '1990-05-15',
    profession: 'solicitor',
    jurisdiction: 'GB',
  };

  it('should issue two credentials (Natural Person + Persona)', async () => {
    const result = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      baseOpts
    );

    expect(result.naturalPerson).toBeDefined();
    expect(result.persona).toBeDefined();
    expect(result.naturalPerson.id).not.toBe(result.persona.id);
  });

  it('Natural Person credential has entity-type, merkle-root, nullifier, age-range', async () => {
    const result = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      baseOpts
    );

    const parsed = parseCredential(result.naturalPerson)!;
    expect(parsed.entityType).toBe('natural_person');
    expect(parsed.nullifier).toBeDefined();
    expect(parsed.merkleRoot).toBeDefined();
    expect(parsed.ageRange).toBe('18+');
    expect(parsed.tier).toBe(3);
    expect(parsed.scope).toBe('adult');
  });

  it('Persona credential has entity-type=persona, age-range, NO nullifier, NO merkle-root', async () => {
    const result = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      baseOpts
    );

    const parsed = parseCredential(result.persona)!;
    expect(parsed.entityType).toBe('persona');
    expect(parsed.ageRange).toBe('18+');
    expect(parsed.nullifier).toBeUndefined();
    expect(parsed.merkleRoot).toBeUndefined();
    expect(parsed.tier).toBe(3);
  });

  it('Merkle leaves can be used for selective disclosure', async () => {
    const result = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      baseOpts
    );

    const parsed = parseCredential(result.naturalPerson)!;
    const nameProof = result.merkleProofs.find(
      (p) => verifyMerkleProof('name', 'Alice Smith', p)
    );
    expect(nameProof).toBeDefined();
    expect(nameProof!.root).toBe(parsed.merkleRoot);
  });

  it('child ceremony includes guardian tags on BOTH credentials', async () => {
    const guardian = generateKeyPair();
    const childNP = generateKeyPair();
    const childPersona = generateKeyPair();

    const result = await createTwoCredentialCeremony(
      verifier.privateKey,
      childNP.publicKey,
      childPersona.publicKey,
      {
        ...baseOpts,
        dateOfBirth: '2016-03-01', // ~10 years old
        guardianPubkeys: [guardian.publicKey],
      }
    );

    const npParsed = parseCredential(result.naturalPerson)!;
    const personaParsed = parseCredential(result.persona)!;

    expect(npParsed.guardianPubkeys).toContain(guardian.publicKey);
    expect(personaParsed.guardianPubkeys).toContain(guardian.publicKey);
    expect(npParsed.tier).toBe(4);
    expect(npParsed.scope).toBe('adult+child');
    expect(npParsed.ageRange).toBe('8-12');
  });

  it('nullifier is deterministic (same inputs = same nullifier)', async () => {
    const result1 = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      baseOpts
    );
    const result2 = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      baseOpts
    );

    const np1 = parseCredential(result1.naturalPerson)!;
    const np2 = parseCredential(result2.naturalPerson)!;
    expect(np1.nullifier).toBe(np2.nullifier);
  });

  it('different documents produce different nullifiers', async () => {
    const result1 = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      baseOpts
    );
    const result2 = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      { ...baseOpts, documentNumber: 'CD789012' }
    );

    const np1 = parseCredential(result1.naturalPerson)!;
    const np2 = parseCredential(result2.naturalPerson)!;
    expect(np1.nullifier).not.toBe(np2.nullifier);
  });

  it('both credentials have valid signatures', async () => {
    const result = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      baseOpts
    );

    const npVerify = await verifyCredential(result.naturalPerson);
    const personaVerify = await verifyCredential(result.persona);

    expect(npVerify.signatureValid).toBe(true);
    expect(personaVerify.signatureValid).toBe(true);
  });

  it('computes correct age ranges for different ages', async () => {
    // Teen (13-17)
    const teen = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      { ...baseOpts, dateOfBirth: '2011-01-15' }
    );
    expect(parseCredential(teen.naturalPerson)!.ageRange).toBe('13-17');

    // Young child (4-7)
    const young = await createTwoCredentialCeremony(
      verifier.privateKey,
      naturalPerson.publicKey,
      persona.publicKey,
      { ...baseOpts, dateOfBirth: '2021-06-15' }
    );
    expect(parseCredential(young.naturalPerson)!.ageRange).toBe('4-7');
  });
});

describe('Credential Chains', () => {
  const verifier = generateKeyPair();
  const subject = generateKeyPair();

  it('superseding credential links to old via supersedes tag', async () => {
    const { naturalPerson: original } = await createTwoCredentialCeremony(
      verifier.privateKey,
      subject.publicKey,
      generateKeyPair().publicKey,
      {
        name: 'Bob Jones',
        nationality: 'US',
        documentType: 'passport',
        documentNumber: 'US111111',
        documentCountry: 'US',
        dateOfBirth: '1985-08-20',
        profession: 'notary',
        jurisdiction: 'US-CA',
      }
    );

    const { newCredential } = await supersedeCredential(
      verifier.privateKey,
      original,
      { subjectPubkey: subject.publicKey }
    );

    const parsed = parseCredential(newCredential)!;
    expect(parsed.supersedes).toBe(original.id);
  });

  it('resolveCredentialChain returns the latest credential', async () => {
    const { naturalPerson: cred1 } = await createTwoCredentialCeremony(
      verifier.privateKey,
      subject.publicKey,
      generateKeyPair().publicKey,
      {
        name: 'Carol White',
        nationality: 'AU',
        documentType: 'passport',
        documentNumber: 'AU222222',
        documentCountry: 'AU',
        dateOfBirth: '1975-03-10',
        profession: 'solicitor',
        jurisdiction: 'AU',
      }
    );

    const { newCredential: cred2, oldCredential: cred1Ref } = await supersedeCredential(
      verifier.privateKey,
      cred1,
      { subjectPubkey: subject.publicKey }
    );

    const chain = resolveCredentialChain([cred1Ref, cred2]);
    expect(chain).not.toBeNull();
    expect(chain!.current.id).toBe(cred2.id);
    expect(chain!.history).toHaveLength(1);
    expect(chain!.history[0].id).toBe(cred1Ref.id);
  });

  it('isSuperseded correctly identifies superseded credentials', async () => {
    const { naturalPerson: original } = await createTwoCredentialCeremony(
      verifier.privateKey,
      subject.publicKey,
      generateKeyPair().publicKey,
      {
        name: 'Dave Brown',
        nationality: 'NZ',
        documentType: 'passport',
        documentNumber: 'NZ333333',
        documentCountry: 'NZ',
        dateOfBirth: '1992-11-05',
        profession: 'notary',
        jurisdiction: 'NZ',
      }
    );

    expect(isSuperseded(original)).toBe(false);

    const { newCredential } = await supersedeCredential(
      verifier.privateKey,
      original,
      { subjectPubkey: subject.publicKey }
    );

    // Old credential is NOT modified (would invalidate its id/sig).
    // Supersession is tracked by the 'supersedes' tag on the new credential.
    expect(isSuperseded(original)).toBe(false);
    const supersedesTag = newCredential.tags.find(t => t[0] === 'supersedes');
    expect(supersedesTag).toBeDefined();
    expect(supersedesTag![1]).toBe(original.id);
  });

  it('chain of 3 resolves correctly', async () => {
    const { naturalPerson: cred1 } = await createTwoCredentialCeremony(
      verifier.privateKey,
      subject.publicKey,
      generateKeyPair().publicKey,
      {
        name: 'Eve Green',
        nationality: 'CA',
        documentType: 'passport',
        documentNumber: 'CA444444',
        documentCountry: 'CA',
        dateOfBirth: '1988-07-22',
        profession: 'notary',
        jurisdiction: 'CA-ON',
      }
    );

    const { newCredential: cred2 } = await supersedeCredential(
      verifier.privateKey,
      cred1,
      { subjectPubkey: subject.publicKey }
    );

    const { newCredential: cred3 } = await supersedeCredential(
      verifier.privateKey,
      cred2,
      { subjectPubkey: subject.publicKey }
    );

    const chain = resolveCredentialChain([cred1, cred2, cred3]);
    expect(chain!.current.id).toBe(cred3.id);
    expect(chain!.history).toHaveLength(2);
    expect(chain!.history[0].id).toBe(cred1.id);
    expect(chain!.history[1].id).toBe(cred2.id);
  });
});

describe('Guardian Delegation', () => {
  const guardian = generateKeyPair();
  const child = generateKeyPair();
  const delegate = generateKeyPair();

  it('creates valid kind 31000 (type: delegation) event', async () => {
    const delegation = await createGuardianDelegation(guardian.privateKey, {
      childPubkey: child.publicKey,
      delegatePubkey: delegate.publicKey,
      scope: 'full',
    });

    expect(delegation.kind).toBe(ATTESTATION_KIND);
    expect(getTagValue(delegation, 'type')).toBe(ATTESTATION_TYPES.DELEGATION);
    expect(delegation.pubkey).toBe(guardian.publicKey);
  });

  it('delegation scope is correctly set', async () => {
    const delegation = await createGuardianDelegation(guardian.privateKey, {
      childPubkey: child.publicKey,
      delegatePubkey: delegate.publicKey,
      scope: 'activity-approval',
    });

    expect(getTagValue(delegation, 'scope')).toBe('activity-approval');
    expect(getTagValue(delegation, 'delegation-type')).toBe('guardian-delegate');
    expect(getTagValue(delegation, 'child')).toBe(child.publicKey);
    expect(getTagValue(delegation, 'p')).toBe(delegate.publicKey);
  });

  it('delegation expires correctly', async () => {
    const expiresAt = Math.floor(Date.now() / 1000) + 86400; // 1 day
    const delegation = await createGuardianDelegation(guardian.privateKey, {
      childPubkey: child.publicKey,
      delegatePubkey: delegate.publicKey,
      scope: 'content-management',
      expiresAt,
    });

    expect(getTagValue(delegation, 'expiration')).toBe(String(expiresAt));
  });

  it('uses guardian-delegate type (not agent type)', async () => {
    const delegation = await createGuardianDelegation(guardian.privateKey, {
      childPubkey: child.publicKey,
      delegatePubkey: delegate.publicKey,
      scope: 'contact-approval',
    });

    expect(getTagValue(delegation, 'delegation-type')).toBe('guardian-delegate');
    // Not an agent delegation
    expect(getTagValue(delegation, 'entity-type')).toBeUndefined();
  });
});

describe('Nullifier Utilities', () => {
  it('computeNullifier produces consistent hex hash', () => {
    const n1 = computeNullifier('passport', 'GB', 'AB123456');
    const n2 = computeNullifier('passport', 'GB', 'AB123456');
    expect(n1).toBe(n2);
    expect(n1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('different document types produce different nullifiers', () => {
    const n1 = computeNullifier('passport', 'GB', 'AB123456');
    const n2 = computeNullifier('national_id', 'GB', 'AB123456');
    expect(n1).not.toBe(n2);
  });

  it('different document numbers produce different nullifiers', () => {
    const n1 = computeNullifier('passport', 'GB', 'AB123456');
    const n2 = computeNullifier('passport', 'GB', 'CD789012');
    expect(n1).not.toBe(n2);
  });

  it('different countries produce different nullifiers', () => {
    const n1 = computeNullifier('passport', 'GB', 'AB123456');
    const n2 = computeNullifier('passport', 'US', 'AB123456');
    expect(n1).not.toBe(n2);
  });

  it('length-prefixed encoding prevents field-boundary collisions', () => {
    // With naive delimiter concatenation, these would collide:
    // "A||B" + "C" + "D" === "A" + "B||C" + "D" (both produce "A||B||C||D||...")
    // With length-prefixed encoding, they must differ.
    const n1 = computeNullifier('passport||GB', 'X', '123');
    const n2 = computeNullifier('passport', 'GB||X', '123');
    expect(n1).not.toBe(n2);
  });

  it('checkNullifierDuplicate detects duplicates', async () => {
    const verifier = generateKeyPair();
    const np = generateKeyPair();
    const persona = generateKeyPair();

    const result = await createTwoCredentialCeremony(
      verifier.privateKey,
      np.publicKey,
      persona.publicKey,
      {
        name: 'Frank Test',
        nationality: 'GB',
        documentType: 'passport',
        documentNumber: 'FRANK001',
        documentCountry: 'GB',
        dateOfBirth: '1980-01-01',
        profession: 'solicitor',
        jurisdiction: 'GB',
      }
    );

    const nullifier = computeNullifier('passport', 'GB', 'FRANK001');
    const check = checkNullifierDuplicate(nullifier, [result.naturalPerson]);
    expect(check.isDuplicate).toBe(true);
    expect(check.conflicting!.id).toBe(result.naturalPerson.id);
  });

  it('checkNullifierDuplicate returns false when no duplicate', () => {
    const nullifier = computeNullifier('passport', 'GB', 'UNIQUE999');
    const check = checkNullifierDuplicate(nullifier, []);
    expect(check.isDuplicate).toBe(false);
    expect(check.conflicting).toBeUndefined();
  });

  it('nullifier chain tag links old nullifier', () => {
    const oldNullifier = computeNullifier('passport', 'GB', 'OLD001');
    const tags = buildNullifierChainTag(oldNullifier);
    expect(tags).toEqual([['nullifier-chain', oldNullifier]]);
  });
});
