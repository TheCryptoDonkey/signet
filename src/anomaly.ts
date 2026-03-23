// Verifier Anomaly Detection
// Statistical analysis of verifier issuance patterns
// Layer 3 of the anti-corruption framework

import { ATTESTATION_KIND, ATTESTATION_TYPES } from './constants.js';
import { getTagValue } from './validation.js';
import type { NostrEvent } from './types.js';

/** Types of anomaly flags */
export type AnomalyType = 'volume' | 'temporal' | 'geographic' | 'pattern';

/** A detected anomaly */
export interface AnomalyFlag {
  type: AnomalyType;
  verifierPubkey: string;
  severity: 'low' | 'medium' | 'high';
  description: string;
  evidence: {
    metric: string;
    value: number;
    threshold: number;
  };
}

/** Anomaly detection configuration */
export interface AnomalyConfig {
  /** Max credentials per week before flagging (default: 20) */
  maxWeeklyVolume: number;
  /** Max credentials per hour before flagging (default: 5) */
  maxHourlyVolume: number;
  /** Max percentage of credentials in a single foreign jurisdiction (default: 30) */
  maxForeignJurisdictionPercent: number;
  /** Min time between consecutive credentials in seconds (default: 300 = 5 min) */
  minTimeBetweenCredentials: number;
  /** Volume multiplier vs network average to flag (default: 5) */
  volumeMultiplierThreshold: number;
}

const DEFAULT_CONFIG: AnomalyConfig = {
  maxWeeklyVolume: 20,
  maxHourlyVolume: 5,
  maxForeignJurisdictionPercent: 30,
  minTimeBetweenCredentials: 300,
  volumeMultiplierThreshold: 5,
};

/**
 * Analyze a verifier's issuance patterns for anomalies.
 *
 * @param verifierPubkey - The verifier to analyze
 * @param allCredentials - All credential events (kind 31000, type: credential) in the store
 * @param verifierCredential - The verifier's own credential (kind 31000, type: verifier)
 * @param config - Detection thresholds
 */
export function detectAnomalies(
  verifierPubkey: string,
  allCredentials: NostrEvent[],
  verifierCredential?: NostrEvent,
  config: Partial<AnomalyConfig> = {}
): AnomalyFlag[] {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const flags: AnomalyFlag[] = [];

  // Get this verifier's issued credentials
  const issued = allCredentials.filter(
    (e) => e.kind === ATTESTATION_KIND && getTagValue(e, 'type') === ATTESTATION_TYPES.CREDENTIAL && e.pubkey === verifierPubkey
  );

  if (issued.length === 0) return flags;

  // Sort by time
  const sorted = [...issued].sort((a, b) => a.created_at - b.created_at);

  // --- Volume Analysis ---
  flags.push(...analyzeVolume(verifierPubkey, sorted, allCredentials, cfg));

  // --- Temporal Analysis ---
  flags.push(...analyzeTemporal(verifierPubkey, sorted, cfg));

  // --- Geographic Analysis ---
  if (verifierCredential) {
    flags.push(...analyzeGeographic(verifierPubkey, sorted, verifierCredential, cfg));
  }

  // --- Pattern Analysis ---
  flags.push(...analyzePatterns(verifierPubkey, sorted));

  return flags;
}

/** Volume anomaly detection */
function analyzeVolume(
  verifierPubkey: string,
  issued: NostrEvent[],
  allCredentials: NostrEvent[],
  cfg: AnomalyConfig
): AnomalyFlag[] {
  const flags: AnomalyFlag[] = [];
  const now = Math.floor(Date.now() / 1000);
  const oneWeek = 7 * 24 * 60 * 60;
  const oneHour = 60 * 60;

  // Weekly volume
  const weeklyCount = issued.filter((e) => e.created_at > now - oneWeek).length;
  if (weeklyCount > cfg.maxWeeklyVolume) {
    flags.push({
      type: 'volume',
      verifierPubkey,
      severity: weeklyCount > cfg.maxWeeklyVolume * 3 ? 'high' : 'medium',
      description: `Issued ${weeklyCount} credentials this week (threshold: ${cfg.maxWeeklyVolume})`,
      evidence: { metric: 'weekly_volume', value: weeklyCount, threshold: cfg.maxWeeklyVolume },
    });
  }

  // Hourly volume (burst detection)
  const hourlyCount = issued.filter((e) => e.created_at > now - oneHour).length;
  if (hourlyCount > cfg.maxHourlyVolume) {
    flags.push({
      type: 'volume',
      verifierPubkey,
      severity: 'high',
      description: `Issued ${hourlyCount} credentials in the last hour (threshold: ${cfg.maxHourlyVolume})`,
      evidence: { metric: 'hourly_volume', value: hourlyCount, threshold: cfg.maxHourlyVolume },
    });
  }

  // Compare to network average
  const allVerifiers = new Set(
    allCredentials.filter((e) => e.kind === ATTESTATION_KIND && getTagValue(e, 'type') === ATTESTATION_TYPES.CREDENTIAL).map((e) => e.pubkey)
  );
  if (allVerifiers.size > 1) {
    const totalCredentials = allCredentials.filter(
      (e) => e.kind === ATTESTATION_KIND && getTagValue(e, 'type') === ATTESTATION_TYPES.CREDENTIAL && e.created_at > now - oneWeek
    ).length;
    const networkAvg = totalCredentials / allVerifiers.size;

    if (networkAvg > 0 && weeklyCount > networkAvg * cfg.volumeMultiplierThreshold) {
      flags.push({
        type: 'volume',
        verifierPubkey,
        severity: 'high',
        description: `Weekly volume ${weeklyCount} is ${(weeklyCount / networkAvg).toFixed(1)}x the network average of ${networkAvg.toFixed(1)}`,
        evidence: {
          metric: 'volume_vs_average',
          value: weeklyCount / networkAvg,
          threshold: cfg.volumeMultiplierThreshold,
        },
      });
    }
  }

  return flags;
}

/** Temporal anomaly detection */
function analyzeTemporal(
  verifierPubkey: string,
  sorted: NostrEvent[],
  cfg: AnomalyConfig
): AnomalyFlag[] {
  const flags: AnomalyFlag[] = [];

  if (sorted.length < 2) return flags;

  // Check minimum time between consecutive credentials
  let rapidCount = 0;
  let minGap = Infinity;

  for (let i = 1; i < sorted.length; i++) {
    const gap = sorted[i].created_at - sorted[i - 1].created_at;
    if (gap < cfg.minTimeBetweenCredentials) {
      rapidCount++;
    }
    if (gap < minGap) minGap = gap;
  }

  if (rapidCount > 0) {
    flags.push({
      type: 'temporal',
      verifierPubkey,
      severity: rapidCount > 5 ? 'high' : 'medium',
      description: `${rapidCount} credential pairs issued less than ${cfg.minTimeBetweenCredentials}s apart (min gap: ${minGap}s). Suggests rubber-stamping, not in-person verification.`,
      evidence: { metric: 'rapid_issuance_count', value: rapidCount, threshold: 0 },
    });
  }

  return flags;
}

/** Geographic anomaly detection */
function analyzeGeographic(
  verifierPubkey: string,
  issued: NostrEvent[],
  verifierCredential: NostrEvent,
  cfg: AnomalyConfig
): AnomalyFlag[] {
  const flags: AnomalyFlag[] = [];

  const verifierJurisdiction = getTagValue(verifierCredential, 'jurisdiction');
  if (!verifierJurisdiction) return flags;

  // Count jurisdictions in issued credentials
  const jurisdictionCounts = new Map<string, number>();
  for (const cred of issued) {
    const j = getTagValue(cred, 'jurisdiction') || 'unknown';
    jurisdictionCounts.set(j, (jurisdictionCounts.get(j) || 0) + 1);
  }

  // Check for high foreign jurisdiction percentage
  for (const [jurisdiction, count] of jurisdictionCounts) {
    if (jurisdiction === verifierJurisdiction) continue;

    const percent = (count / issued.length) * 100;
    if (percent > cfg.maxForeignJurisdictionPercent) {
      flags.push({
        type: 'geographic',
        verifierPubkey,
        severity: percent > 60 ? 'high' : 'medium',
        description: `${percent.toFixed(0)}% of credentials (${count}/${issued.length}) issued in ${jurisdiction}, but verifier is registered in ${verifierJurisdiction}`,
        evidence: {
          metric: 'foreign_jurisdiction_percent',
          value: percent,
          threshold: cfg.maxForeignJurisdictionPercent,
        },
      });
    }
  }

  return flags;
}

/** Pattern anomaly detection */
function analyzePatterns(
  verifierPubkey: string,
  sorted: NostrEvent[]
): AnomalyFlag[] {
  const flags: AnomalyFlag[] = [];

  if (sorted.length < 5) return flags;

  // Check for repeated subjects (same person verified multiple times)
  const subjectCounts = new Map<string, number>();
  for (const cred of sorted) {
    const subject = getTagValue(cred, 'd') || '';
    subjectCounts.set(subject, (subjectCounts.get(subject) || 0) + 1);
  }

  const duplicates = Array.from(subjectCounts.entries()).filter(([, count]) => count > 1);
  if (duplicates.length > 0) {
    const totalDupes = duplicates.reduce((sum, [, count]) => sum + count - 1, 0);
    flags.push({
      type: 'pattern',
      verifierPubkey,
      severity: 'low',
      description: `${duplicates.length} subjects verified multiple times (${totalDupes} extra verifications)`,
      evidence: { metric: 'duplicate_subjects', value: duplicates.length, threshold: 0 },
    });
  }

  // Check for disproportionate tier 4 issuance
  let tier4Count = 0;
  for (const cred of sorted) {
    if (getTagValue(cred, 'tier') === '4') tier4Count++;
  }

  const tier4Percent = (tier4Count / sorted.length) * 100;
  if (tier4Count > 3 && tier4Percent > 80) {
    flags.push({
      type: 'pattern',
      verifierPubkey,
      severity: 'medium',
      description: `${tier4Percent.toFixed(0)}% of credentials are Tier 4 (${tier4Count}/${sorted.length}). Unusually high child verification rate.`,
      evidence: { metric: 'tier4_percent', value: tier4Percent, threshold: 80 },
    });
  }

  return flags;
}

/**
 * Get a summary of all flagged verifiers from a set of credentials.
 */
export function scanForAnomalies(
  allCredentials: NostrEvent[],
  verifierCredentials: NostrEvent[],
  config?: Partial<AnomalyConfig>
): Map<string, AnomalyFlag[]> {
  const results = new Map<string, AnomalyFlag[]>();

  // Get unique verifier pubkeys from credentials
  const verifiers = new Set(
    allCredentials
      .filter((e) => e.kind === ATTESTATION_KIND && getTagValue(e, 'type') === ATTESTATION_TYPES.CREDENTIAL)
      .map((e) => e.pubkey)
  );

  for (const pubkey of verifiers) {
    const verifierCred = verifierCredentials.find((c) => c.pubkey === pubkey);
    const flags = detectAnomalies(pubkey, allCredentials, verifierCred, config);

    if (flags.length > 0) {
      results.set(pubkey, flags);
    }
  }

  return results;
}
