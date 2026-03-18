// Example: Full "Signet Me" Flow
// Profile creation → backup → connection → verification words
//
// Run: npx tsx examples/signet-me.ts

import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToEntropy,
  entropyToMnemonic,
  createSignetIdentity,
  deriveAdditionalPersona,
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  computeSharedSecret,
  createConnection,
  getSignetWords,
  verifySignetWords,
  formatSignetWords,
  getSignetDisplay,
} from '../src/index.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// ─────────────────────────────────────────────────────────────────────────────
// Step 1: Alice creates her identity
// ─────────────────────────────────────────────────────────────────────────────

console.log('═══════════════════════════════════════════════════');
console.log('  STEP 1: Profile Creation');
console.log('═══════════════════════════════════════════════════\n');

const aliceMnemonic = generateMnemonic();
const aliceIdentity = createSignetIdentity(aliceMnemonic);
const alice = {
  privateKey: bytesToHex(aliceIdentity.naturalPerson.identity.privateKey),
  publicKey: bytesToHex(aliceIdentity.naturalPerson.identity.publicKey),
};

console.log('Alice creates a new Signet identity:\n');
console.log(`  Mnemonic:    ${aliceMnemonic}`);
console.log(`  Public Key:  ${alice.publicKey.slice(0, 16)}...`);
console.log(`  Valid:        ${validateMnemonic(aliceMnemonic)}`);

// Alice also derives a child persona
const aliceChildPersona = deriveAdditionalPersona(aliceIdentity.root, 'child', 0);
const aliceChild = {
  publicKey: bytesToHex(aliceChildPersona.identity.publicKey),
};
console.log(`\n  Child's Key: ${aliceChild.publicKey.slice(0, 16)}... (persona: child)`);
aliceIdentity.root.destroy();

// ─────────────────────────────────────────────────────────────────────────────
// Step 2: Alice backs up her seed using Shamir's Secret Sharing
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════');
console.log('  STEP 2: Shared Backup (Shamir 2-of-3)');
console.log('═══════════════════════════════════════════════════\n');

const entropy = mnemonicToEntropy(aliceMnemonic);
const shares = splitSecret(entropy, 2, 3);

console.log('Alice splits her seed into 3 shares (any 2 reconstruct):\n');
for (const share of shares) {
  const words = shareToWords(share);
  console.log(`  Share ${share.id}: ${words.slice(0, 4).join(' ')}... (${words.length} words)`);
}

// Verify reconstruction with shares 1 and 3 (skipping share 2)
const reconstructed = reconstructSecret(
  [wordsToShare(shareToWords(shares[0])), wordsToShare(shareToWords(shares[2]))],
  2
);
const reconstructedMnemonic = entropyToMnemonic(reconstructed);
console.log(`\n  Reconstructed from shares 1 + 3: ${reconstructedMnemonic === aliceMnemonic ? 'SUCCESS ✓' : 'FAILED ✗'}`);

// ─────────────────────────────────────────────────────────────────────────────
// Step 3: Bob creates his identity
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════');
console.log('  STEP 3: Bob Creates His Identity');
console.log('═══════════════════════════════════════════════════\n');

const bobMnemonic = generateMnemonic();
const bobIdentity = createSignetIdentity(bobMnemonic);
const bob = {
  privateKey: bytesToHex(bobIdentity.naturalPerson.identity.privateKey),
  publicKey: bytesToHex(bobIdentity.naturalPerson.identity.publicKey),
};
const bobChildPersona = deriveAdditionalPersona(bobIdentity.root, 'child', 0);
const bobChild = {
  publicKey: bytesToHex(bobChildPersona.identity.publicKey),
};
bobIdentity.root.destroy();

console.log(`Bob's identity:`);
console.log(`  Public Key:  ${bob.publicKey.slice(0, 16)}...`);
console.log(`  Child's Key: ${bobChild.publicKey.slice(0, 16)}...`);

// ─────────────────────────────────────────────────────────────────────────────
// Step 4: Alice and Bob meet in person — QR code exchange
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════');
console.log('  STEP 4: In-Person Connection (QR Exchange)');
console.log('═══════════════════════════════════════════════════\n');

// Alice shows her QR code with selected contact info
const aliceQR = createQRPayload(alice.publicKey, {
  name: 'Alice',
  mobile: '+44 7700 900000',
  childPubkeys: [aliceChild.publicKey],
});

// Bob shows his QR code
const bobQR = createQRPayload(bob.publicKey, {
  name: 'Bob',
  mobile: '+44 7700 900001',
  address: '42 Oak Lane, London',
  childPubkeys: [bobChild.publicKey],
});

console.log('Alice and Bob meet at a local meetup. They scan each other\'s QR codes.\n');

// Simulate the QR scan — each party scans the other's serialized payload
const aliceScannedBob = parseQRPayload(serializeQRPayload(bobQR));
const bobScannedAlice = parseQRPayload(serializeQRPayload(aliceQR));

// Each creates a connection
const aliceConnection = createConnection(alice.privateKey, aliceScannedBob, {
  name: 'Alice',
  mobile: '+44 7700 900000',
  childPubkeys: [aliceChild.publicKey],
});

const bobConnection = createConnection(bob.privateKey, bobScannedAlice, {
  name: 'Bob',
  mobile: '+44 7700 900001',
  address: '42 Oak Lane, London',
  childPubkeys: [bobChild.publicKey],
});

console.log(`Alice → Bob shared secret: ${aliceConnection.sharedSecret.slice(0, 16)}...`);
console.log(`Bob → Alice shared secret: ${bobConnection.sharedSecret.slice(0, 16)}...`);
console.log(`Secrets match:             ${aliceConnection.sharedSecret === bobConnection.sharedSecret ? 'YES ✓' : 'NO ✗'}`);
console.log(`\nAlice sees Bob's info:`);
console.log(`  Name:   ${aliceConnection.theirInfo.name}`);
console.log(`  Mobile: ${aliceConnection.theirInfo.mobile}`);
console.log(`  Kids:   ${aliceConnection.theirInfo.childPubkeys?.length} child key(s)`);
console.log(`\nBob sees Alice's info:`);
console.log(`  Name:   ${bobConnection.theirInfo.name}`);
console.log(`  Mobile: ${bobConnection.theirInfo.mobile}`);
console.log(`  Kids:   ${bobConnection.theirInfo.childPubkeys?.length} child key(s)`);

// ─────────────────────────────────────────────────────────────────────────────
// Step 5: Months later — Bob calls Alice asking for money
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════');
console.log('  STEP 5: "Signet Me" — Phone Verification');
console.log('═══════════════════════════════════════════════════\n');

console.log('Six months later, Bob calls Alice:');
console.log('"Hey Alice, it\'s Bob. I\'m in a tight spot — can you send');
console.log(' some cash to my new bank account?"');
console.log('');
console.log('Alice: "Sure, no problem. Signet me first."\n');

// Both open each other's profiles at the same time
const now = Date.now();

const aliceSees = getSignetDisplay(aliceConnection.sharedSecret, now);
const bobSees = getSignetDisplay(bobConnection.sharedSecret, now);

console.log('Alice opens Bob\'s profile and sees:');
console.log(`  My Signet: ${aliceSees.formatted}`);
console.log(`  Expires in: ${aliceSees.expiresIn.toFixed(0)}s`);
console.log('');
console.log('Bob opens Alice\'s profile and sees:');
console.log(`  My Signet: ${bobSees.formatted}`);
console.log(`  Expires in: ${bobSees.expiresIn.toFixed(0)}s`);
console.log('');
console.log(`Words match: ${aliceSees.formatted === bobSees.formatted ? 'YES ✓' : 'NO ✗'}`);

// Bob reads the words to Alice
const bobReadsWords = getSignetWords(bobConnection.sharedSecret, now);
const aliceVerifies = verifySignetWords(aliceConnection.sharedSecret, bobReadsWords, now);

console.log(`\nBob reads: "${formatSignetWords(bobReadsWords)}"`);
console.log(`Alice verifies: ${aliceVerifies ? 'MATCH ✓ — It\'s really Bob!' : 'NO MATCH ✗ — Impostor!'}`);

// ─────────────────────────────────────────────────────────────────────────────
// Step 6: Demonstrating word rotation
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════');
console.log('  STEP 6: Word Rotation');
console.log('═══════════════════════════════════════════════════\n');

console.log('Words rotate every 30 seconds:\n');
for (let i = 0; i < 4; i++) {
  const futureTime = now + i * 30_000;
  const words = getSignetWords(aliceConnection.sharedSecret, futureTime);
  const label = i === 0 ? 'Now     ' : `+${i * 30}s     `;
  console.log(`  ${label} ${formatSignetWords(words)}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Step 7: Bank scenario
// ─────────────────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════');
console.log('  STEP 7: Bank Verification');
console.log('═══════════════════════════════════════════════════\n');

// The bank has a Nostr keypair too
const bankMnemonic = generateMnemonic();
const bankIdentity = createSignetIdentity(bankMnemonic);
const bank = {
  privateKey: bytesToHex(bankIdentity.naturalPerson.identity.privateKey),
  publicKey: bytesToHex(bankIdentity.naturalPerson.identity.publicKey),
};
bankIdentity.root.destroy();

// Alice visits the bank and scans their QR code
const bankQR = createQRPayload(bank.publicKey, { name: 'High Street Bank' });
const aliceBankConnection = createConnection(alice.privateKey, parseQRPayload(serializeQRPayload(bankQR)), {
  name: 'Alice',
});

// Bank also stores the connection
const bankAliceSecret = computeSharedSecret(bank.privateKey, alice.publicKey);

console.log('"The bank" calls Alice about suspicious activity.\n');
console.log('Alice: "Read me my signet."\n');

const bankNow = Date.now();
const bankWords = getSignetWords(bankAliceSecret, bankNow);
const aliceBankWords = getSignetWords(aliceBankConnection.sharedSecret, bankNow);

console.log(`Bank agent reads:  ${formatSignetWords(bankWords)}`);
console.log(`Alice sees:        ${formatSignetWords(aliceBankWords)}`);
console.log(`Match:             ${formatSignetWords(bankWords) === formatSignetWords(aliceBankWords) ? 'YES ✓ — It\'s really the bank.' : 'NO ✗ — Scam call!'}`);

console.log('\n═══════════════════════════════════════════════════');
console.log('  Done. Your signet is your proof.');
console.log('═══════════════════════════════════════════════════');
