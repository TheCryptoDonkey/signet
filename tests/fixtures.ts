import { generateKeyPair, createProfessionalCredential } from '../src/index.js';

/** Standard BIP-39 test mnemonic (all "abandon" + "about") */
export const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** Standard Tier 3 credential options used across many tests */
export const TIER3_OPTS = { profession: 'solicitor', jurisdiction: 'UK' } as const;

/** Generate an array of N keypairs */
export function generateKeypairs(n: number) {
  return Array.from({ length: n }, () => generateKeyPair());
}

/** Create a standard Tier 3 test credential */
export async function createTestCredential(opts?: {
  verifierPrivateKey?: string;
  subjectPubkey?: string;
  profession?: string;
  jurisdiction?: string;
  expiresAt?: number;
}) {
  const verifier = opts?.verifierPrivateKey ? { privateKey: opts.verifierPrivateKey } : generateKeyPair();
  const subject = opts?.subjectPubkey ? { publicKey: opts.subjectPubkey } : generateKeyPair();
  return createProfessionalCredential(verifier.privateKey, subject.publicKey, {
    profession: opts?.profession ?? 'solicitor',
    jurisdiction: opts?.jurisdiction ?? 'UK',
    expiresAt: opts?.expiresAt,
  });
}
