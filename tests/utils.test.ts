import { describe, it, expect } from 'vitest';
import { zeroBytes, constantTimeEqual } from '../src/utils.js';

describe('zeroBytes', () => {
  it('fills a Uint8Array with zeros', () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    zeroBytes(buf);
    expect(buf).toEqual(new Uint8Array(5));
  });

  it('handles empty array', () => {
    const buf = new Uint8Array(0);
    zeroBytes(buf);
    expect(buf.length).toBe(0);
  });
});

describe('constantTimeEqual', () => {
  it('returns true for equal arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it('returns false for different arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it('returns false for different lengths', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([1, 2, 3]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it('handles empty arrays', () => {
    const a = new Uint8Array(0);
    const b = new Uint8Array(0);
    expect(constantTimeEqual(a, b)).toBe(true);
  });
});
