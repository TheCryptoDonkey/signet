import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../src/crypto.js';
import { detectAnomalies, scanForAnomalies } from '../src/anomaly.js';
import {
  createProfessionalCredential,
  createChildSafetyCredential,
  createSelfDeclaredCredential,
  createVerifierCredential,
} from '../src/index.js';
import type { NostrEvent } from '../src/types.js';

describe('anomaly detection', () => {
  async function makeCredentials(
    verifierKey: { privateKey: string; publicKey: string },
    count: number,
    opts: { timeGap?: number; jurisdiction?: string; tier4?: boolean } = {}
  ): Promise<NostrEvent[]> {
    const creds: NostrEvent[] = [];
    const now = Math.floor(Date.now() / 1000);

    for (let i = 0; i < count; i++) {
      const subject = generateKeyPair();
      const tier1 = await createSelfDeclaredCredential(subject.privateKey);
      let cred: NostrEvent;

      if (opts.tier4) {
        cred = await createChildSafetyCredential(verifierKey.privateKey, subject.publicKey, {
          assertionEventId: tier1.id,
          profession: 'solicitor',
          jurisdiction: opts.jurisdiction || 'UK',
          ageRange: '8-12',
          actualAge: 10,
        });
      } else {
        cred = await createProfessionalCredential(verifierKey.privateKey, subject.publicKey, {
          assertionEventId: tier1.id,
          profession: 'solicitor',
          jurisdiction: opts.jurisdiction || 'UK',
          actualAge: 25,
        });
      }

      // Override created_at for testing
      (cred as any).created_at = now - i * (opts.timeGap ?? 3600);
      creds.push(cred);
    }

    return creds;
  }

  it('flags high weekly volume', async () => {
    const verifier = generateKeyPair();
    const creds = await makeCredentials(verifier, 25, { timeGap: 3600 }); // 25 in ~1 day

    const flags = detectAnomalies(verifier.publicKey, creds, undefined, {
      maxWeeklyVolume: 20,
    });

    expect(flags.some((f) => f.type === 'volume')).toBe(true);
  }, 60000);

  it('flags hourly burst', async () => {
    const verifier = generateKeyPair();
    const creds = await makeCredentials(verifier, 8, { timeGap: 60 }); // 8 in 8 minutes

    const flags = detectAnomalies(verifier.publicKey, creds, undefined, {
      maxHourlyVolume: 5,
    });

    expect(flags.some((f) => f.type === 'volume' && f.description.includes('hour'))).toBe(true);
  });

  it('flags rapid consecutive issuance', async () => {
    const verifier = generateKeyPair();
    const creds = await makeCredentials(verifier, 5, { timeGap: 60 }); // 1 minute apart

    const flags = detectAnomalies(verifier.publicKey, creds, undefined, {
      minTimeBetweenCredentials: 300,
    });

    expect(flags.some((f) => f.type === 'temporal')).toBe(true);
  });

  it('flags foreign jurisdiction issuance', async () => {
    const verifier = generateKeyPair();
    const verifierCred = await createVerifierCredential(verifier.privateKey, {
      profession: 'solicitor',
      jurisdiction: 'UK',
      licenceHash: 'hash123',
      professionalBody: 'Law Society',
    });

    // Create credentials in a foreign jurisdiction
    const creds = await makeCredentials(verifier, 5, { jurisdiction: 'JP' });

    const flags = detectAnomalies(verifier.publicKey, creds, verifierCred, {
      maxForeignJurisdictionPercent: 30,
    });

    expect(flags.some((f) => f.type === 'geographic')).toBe(true);
  });

  it('no flags for normal activity', async () => {
    const verifier = generateKeyPair();
    const creds = await makeCredentials(verifier, 3, { timeGap: 86400 }); // 3 over 3 days

    const flags = detectAnomalies(verifier.publicKey, creds, undefined, {
      maxWeeklyVolume: 20,
      maxHourlyVolume: 5,
      minTimeBetweenCredentials: 300,
    });

    // Only pattern flags possible (duplicate detection etc), not volume/temporal
    const volumeOrTemporal = flags.filter((f) => f.type === 'volume' || f.type === 'temporal');
    expect(volumeOrTemporal).toHaveLength(0);
  });

  it('scanForAnomalies scans all verifiers', async () => {
    const v1 = generateKeyPair();
    const v2 = generateKeyPair();

    const creds1 = await makeCredentials(v1, 25, { timeGap: 3600 });
    const creds2 = await makeCredentials(v2, 2, { timeGap: 86400 });

    const allCreds = [...creds1, ...creds2];
    const results = scanForAnomalies(allCreds, [], { maxWeeklyVolume: 20 });

    // v1 should be flagged, v2 should not
    expect(results.has(v1.publicKey)).toBe(true);
    expect(results.has(v2.publicKey)).toBe(false);
  }, 60000);
});
