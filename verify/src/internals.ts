/**
 * Internal barrel — re-exports testable helpers from signet-verify.ts.
 * Not part of the public API; for use in tests only.
 */
export {
  verifyEventSignature,
  ageRangeSatisfies,
  escapeHtml,
  getTagValue,
  generateRequestId,
  checkVerifierStatus,
} from './signet-verify';
