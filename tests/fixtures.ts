import { generateKeyPair, createProfessionalCredential, createSelfDeclaredCredential, getPublicKey } from '../src/index.js';

/** Standard BIP-39 test mnemonic (all "abandon" + "about") */
export const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** Generate an array of N keypairs */
export function generateKeypairs(n: number) {
  return Array.from({ length: n }, () => generateKeyPair());
}

/** Create a Tier 1 self-declaration for a subject (needed as assertion for Tier 2-4) */
export async function createTestTier1(subjectPrivateKey: string) {
  return createSelfDeclaredCredential(subjectPrivateKey);
}

/** Build Tier 3 opts with assertion event ID from a fresh Tier 1.
 * Use when you need opts for createProfessionalCredential in tests. */
export async function buildTier3Opts(subjectPrivateKey: string, extra?: {
  profession?: string;
  jurisdiction?: string;
  expiresAt?: number;
  occurredAt?: number;
  proofBlob?: string;
}) {
  const tier1 = await createSelfDeclaredCredential(subjectPrivateKey);
  return {
    assertionEventId: tier1.id,
    profession: extra?.profession ?? 'solicitor',
    jurisdiction: extra?.jurisdiction ?? 'UK',
    expiresAt: extra?.expiresAt,
    occurredAt: extra?.occurredAt,
    proofBlob: extra?.proofBlob,
  };
}

/** Create a standard Tier 3 test credential with assertion-first pattern */
export async function createTestCredential(opts?: {
  verifierPrivateKey?: string;
  subjectPrivateKey?: string;
  profession?: string;
  jurisdiction?: string;
  expiresAt?: number;
}) {
  const verifier = opts?.verifierPrivateKey ? { privateKey: opts.verifierPrivateKey } : generateKeyPair();
  const subject = opts?.subjectPrivateKey
    ? { privateKey: opts.subjectPrivateKey, publicKey: getPublicKey(opts.subjectPrivateKey) }
    : generateKeyPair();

  const tier3Opts = await buildTier3Opts(subject.privateKey, {
    profession: opts?.profession,
    jurisdiction: opts?.jurisdiction,
    expiresAt: opts?.expiresAt,
  });

  return createProfessionalCredential(verifier.privateKey, subject.publicKey, tier3Opts);
}
