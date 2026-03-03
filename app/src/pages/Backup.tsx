import { useState, useCallback } from 'react';
import type { StoredIdentity } from '../lib/db';
import {
  mnemonicToEntropy,
  entropyToMnemonic,
  splitSecret,
  reconstructSecret,
  shareToWords,
  wordsToShare,
  validateMnemonic,
} from '../lib/signet';
import type { ShamirShare } from '../lib/signet';
import { QRCode } from '../components/QRCode';

interface BackupProps {
  identity: StoredIdentity;
  onBack?: () => void;
}

type Scheme = '2-of-3' | '3-of-5';

interface SchemeConfig {
  threshold: number;
  total: number;
  label: string;
}

const SCHEMES: Record<Scheme, SchemeConfig> = {
  '2-of-3': { threshold: 2, total: 3, label: '2-of-3 (recommended)' },
  '3-of-5': { threshold: 3, total: 5, label: '3-of-5' },
};

// ---- Section: Create Backup Shares ----

function CreateShares({ identity }: { identity: StoredIdentity }) {
  const [showMnemonic, setShowMnemonic] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [scheme, setScheme] = useState<Scheme>('2-of-3');
  const [shares, setShares] = useState<{ words: string[]; share: ShamirShare }[] | null>(null);
  const [expandedShare, setExpandedShare] = useState<number | null>(null);

  const words = (identity.mnemonic ?? '').split(' ');

  const handleReveal = useCallback(() => {
    setShowMnemonic(true);
  }, []);

  const handleGenerateShares = useCallback(() => {
    const config = SCHEMES[scheme];
    const entropy = mnemonicToEntropy(identity.mnemonic!);
    const shamirShares = splitSecret(entropy, config.threshold, config.total);
    const result = shamirShares.map((s) => ({
      share: s,
      words: shareToWords(s),
    }));
    setShares(result);
    setExpandedShare(0);
  }, [identity.mnemonic, scheme]);

  const toggleShare = useCallback((index: number) => {
    setExpandedShare((prev) => (prev === index ? null : index));
  }, []);

  return (
    <div>
      {/* Section heading */}
      <h2
        style={{
          fontSize: 20,
          fontWeight: 700,
          color: 'var(--text-primary)',
          marginBottom: 4,
        }}
      >
        Create Backup Shares
      </h2>
      <p
        style={{
          fontSize: 13,
          color: 'var(--text-secondary)',
          marginBottom: 20,
          lineHeight: 1.5,
        }}
      >
        Split your recovery phrase into shares using Shamir&apos;s Secret Sharing. Store each share
        in a different safe location.
      </p>

      {/* Reveal Mnemonic */}
      <div
        className="card"
        style={{
          marginBottom: 16,
          padding: 20,
        }}
      >
        <h3
          style={{
            fontSize: 15,
            fontWeight: 600,
            color: 'var(--text-primary)',
            marginBottom: 12,
          }}
        >
          Recovery Phrase
        </h3>

        {!showMnemonic ? (
          <div>
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                cursor: 'pointer',
                marginBottom: 14,
                minHeight: 44,
                WebkitTapHighlightColor: 'transparent',
              }}
            >
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                style={{
                  width: 20,
                  height: 20,
                  accentColor: 'var(--accent)',
                  flexShrink: 0,
                }}
              />
              <span style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.4 }}>
                I understand the risks of revealing my recovery phrase
              </span>
            </label>
            <button
              className="btn btn-secondary"
              style={{ width: '100%' }}
              disabled={!confirmed}
              onClick={handleReveal}
            >
              Show Recovery Phrase
            </button>
          </div>
        ) : (
          <div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: 8,
                marginBottom: 12,
              }}
            >
              {words.map((word, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    background: 'var(--bg-input)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '8px 10px',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <span
                    style={{
                      fontSize: 11,
                      fontWeight: 600,
                      color: 'var(--text-muted)',
                      minWidth: 18,
                    }}
                  >
                    {i + 1}.
                  </span>
                  <span
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color: 'var(--signet-word)',
                      fontFamily: 'monospace',
                    }}
                  >
                    {word}
                  </span>
                </div>
              ))}
            </div>
            <button
              className="btn btn-secondary"
              style={{ width: '100%' }}
              onClick={() => {
                setShowMnemonic(false);
                setConfirmed(false);
              }}
            >
              Hide Recovery Phrase
            </button>
          </div>
        )}
      </div>

      {/* Shamir Split */}
      <div
        className="card"
        style={{
          marginBottom: 16,
          padding: 20,
        }}
      >
        <h3
          style={{
            fontSize: 15,
            fontWeight: 600,
            color: 'var(--text-primary)',
            marginBottom: 12,
          }}
        >
          Shamir Split
        </h3>

        <p
          style={{
            fontSize: 13,
            color: 'var(--text-secondary)',
            marginBottom: 14,
            lineHeight: 1.4,
          }}
        >
          Choose a splitting scheme. Any subset of shares meeting the threshold can reconstruct
          your recovery phrase.
        </p>

        {/* Scheme selector */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          {(Object.keys(SCHEMES) as Scheme[]).map((key) => (
            <button
              key={key}
              onClick={() => {
                setScheme(key);
                setShares(null);
              }}
              style={{
                flex: 1,
                padding: '10px 8px',
                borderRadius: 'var(--radius-sm)',
                border: `2px solid ${scheme === key ? 'var(--accent)' : 'var(--border)'}`,
                background: scheme === key ? 'var(--accent)' : 'var(--bg-input)',
                color: scheme === key ? 'var(--accent-text)' : 'var(--text-primary)',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
                minHeight: 44,
                transition: 'background 0.15s, border-color 0.15s, color 0.15s',
                WebkitTapHighlightColor: 'transparent',
              }}
            >
              {SCHEMES[key].label}
            </button>
          ))}
        </div>

        <button
          className="btn btn-primary"
          style={{ width: '100%' }}
          onClick={handleGenerateShares}
        >
          Generate Shares
        </button>
      </div>

      {/* Generated shares */}
      {shares && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <p
            style={{
              fontSize: 13,
              color: 'var(--warning)',
              fontWeight: 600,
              lineHeight: 1.4,
              marginBottom: 4,
            }}
          >
            Store each share separately. Never keep all shares in the same place.
          </p>
          {shares.map((s, i) => {
            const isExpanded = expandedShare === i;
            const qrData = JSON.stringify(s.words);

            return (
              <div
                key={i}
                className="card"
                style={{
                  padding: 0,
                  overflow: 'hidden',
                }}
              >
                {/* Header - always visible */}
                <button
                  onClick={() => toggleShare(i)}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '14px 18px',
                    background: 'transparent',
                    border: 'none',
                    cursor: 'pointer',
                    minHeight: 44,
                    WebkitTapHighlightColor: 'transparent',
                  }}
                >
                  <span
                    style={{
                      fontSize: 15,
                      fontWeight: 600,
                      color: 'var(--text-primary)',
                    }}
                  >
                    Share {i + 1} of {SCHEMES[scheme].total}
                  </span>
                  <span
                    style={{
                      fontSize: 18,
                      color: 'var(--text-muted)',
                      transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.2s',
                      display: 'inline-block',
                    }}
                  >
                    &#9660;
                  </span>
                </button>

                {/* Body - collapsible */}
                {isExpanded && (
                  <div style={{ padding: '0 18px 18px 18px' }}>
                    {/* Share words */}
                    <div
                      style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: 6,
                        marginBottom: 14,
                      }}
                    >
                      {s.words.map((word, wi) => (
                        <span
                          key={wi}
                          style={{
                            display: 'inline-block',
                            background: 'var(--bg-input)',
                            borderRadius: 'var(--radius-sm)',
                            padding: '4px 8px',
                            fontSize: 12,
                            fontWeight: 600,
                            fontFamily: 'monospace',
                            color: 'var(--signet-word)',
                            border: '1px solid var(--border-subtle)',
                          }}
                        >
                          {word}
                        </span>
                      ))}
                    </div>

                    {/* QR Code */}
                    <QRCode data={qrData} size={150} />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---- Section: Restore from Shares ----

function RestoreFromShares() {
  const [scheme, setScheme] = useState<Scheme>('2-of-3');
  const [inputs, setInputs] = useState<string[]>(() =>
    Array(SCHEMES['2-of-3'].threshold).fill(''),
  );
  const [result, setResult] = useState<
    { success: true; mnemonic: string } | { success: false; error: string } | null
  >(null);

  const handleSchemeChange = useCallback((newScheme: Scheme) => {
    setScheme(newScheme);
    setInputs(Array(SCHEMES[newScheme].threshold).fill(''));
    setResult(null);
  }, []);

  const handleInputChange = useCallback((index: number, value: string) => {
    setInputs((prev) => {
      const next = [...prev];
      next[index] = value;
      return next;
    });
    setResult(null);
  }, []);

  const handleReconstruct = useCallback(() => {
    try {
      const config = SCHEMES[scheme];
      const parsedShares: ShamirShare[] = inputs.map((text) => {
        const words = text.trim().split(/\s+/);
        if (words.length === 0 || (words.length === 1 && words[0] === '')) {
          throw new Error('Empty share input. Enter the share words.');
        }
        return wordsToShare(words);
      });

      const entropy = reconstructSecret(parsedShares, config.threshold);
      const recovered = entropyToMnemonic(entropy);

      if (validateMnemonic(recovered)) {
        setResult({ success: true, mnemonic: recovered });
      } else {
        setResult({ success: false, error: 'Reconstruction produced an invalid mnemonic. Check your shares and try again.' });
      }
    } catch (err) {
      setResult({
        success: false,
        error: err instanceof Error ? err.message : 'Reconstruction failed',
      });
    }
  }, [scheme, inputs]);

  const allFilled = inputs.every((s) => s.trim().length > 0);

  return (
    <div>
      <h2
        style={{
          fontSize: 20,
          fontWeight: 700,
          color: 'var(--text-primary)',
          marginBottom: 4,
        }}
      >
        Restore from Shares
      </h2>
      <p
        style={{
          fontSize: 13,
          color: 'var(--text-secondary)',
          marginBottom: 20,
          lineHeight: 1.5,
        }}
      >
        Enter enough Shamir shares to reconstruct your recovery phrase.
      </p>

      {/* Scheme selector */}
      <div
        className="card"
        style={{
          marginBottom: 16,
          padding: 20,
        }}
      >
        <h3
          style={{
            fontSize: 15,
            fontWeight: 600,
            color: 'var(--text-primary)',
            marginBottom: 12,
          }}
        >
          Select Scheme
        </h3>
        <div style={{ display: 'flex', gap: 8 }}>
          {(Object.keys(SCHEMES) as Scheme[]).map((key) => (
            <button
              key={key}
              onClick={() => handleSchemeChange(key)}
              style={{
                flex: 1,
                padding: '10px 8px',
                borderRadius: 'var(--radius-sm)',
                border: `2px solid ${scheme === key ? 'var(--accent)' : 'var(--border)'}`,
                background: scheme === key ? 'var(--accent)' : 'var(--bg-input)',
                color: scheme === key ? 'var(--accent-text)' : 'var(--text-primary)',
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
                minHeight: 44,
                transition: 'background 0.15s, border-color 0.15s, color 0.15s',
                WebkitTapHighlightColor: 'transparent',
              }}
            >
              {SCHEMES[key].label}
            </button>
          ))}
        </div>
      </div>

      {/* Share inputs */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
        {inputs.map((value, i) => (
          <div
            key={`${scheme}-${i}`}
            className="card"
            style={{ padding: 16 }}
          >
            <label
              style={{
                display: 'block',
                fontSize: 14,
                fontWeight: 600,
                color: 'var(--text-primary)',
                marginBottom: 8,
              }}
            >
              Share {i + 1}
            </label>
            <textarea
              className="input"
              value={value}
              onChange={(e) => handleInputChange(i, e.target.value)}
              placeholder={`Paste or type share ${i + 1} words here...`}
              rows={3}
              style={{
                resize: 'none',
                fontFamily: 'monospace',
                fontSize: 13,
                lineHeight: 1.5,
                width: '100%',
                boxSizing: 'border-box',
              }}
            />
          </div>
        ))}
      </div>

      {/* Reconstruct button */}
      <button
        className="btn btn-primary"
        style={{ width: '100%', marginBottom: 16 }}
        disabled={!allFilled}
        onClick={handleReconstruct}
      >
        Reconstruct Recovery Phrase
      </button>

      {/* Result */}
      {result && !result.success && (
        <div
          className="card"
          style={{
            padding: 16,
            borderColor: 'var(--danger)',
          }}
        >
          <p
            style={{
              fontSize: 14,
              fontWeight: 600,
              color: 'var(--danger)',
              marginBottom: 4,
            }}
          >
            Reconstruction Failed
          </p>
          <p
            style={{
              fontSize: 13,
              color: 'var(--text-secondary)',
              lineHeight: 1.4,
            }}
          >
            {result.error}
          </p>
        </div>
      )}

      {result && result.success && (
        <div
          className="card"
          style={{
            padding: 20,
            borderColor: 'var(--success)',
          }}
        >
          <p
            style={{
              fontSize: 14,
              fontWeight: 600,
              color: 'var(--success)',
              marginBottom: 12,
            }}
          >
            Recovery Phrase Reconstructed Successfully
          </p>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: 8,
            }}
          >
            {result.mnemonic.split(' ').map((word, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  background: 'var(--bg-input)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '8px 10px',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    color: 'var(--text-muted)',
                    minWidth: 18,
                  }}
                >
                  {i + 1}.
                </span>
                <span
                  style={{
                    fontSize: 13,
                    fontWeight: 600,
                    color: 'var(--signet-word)',
                    fontFamily: 'monospace',
                  }}
                >
                  {word}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---- Main Backup Component ----

export function Backup({ identity, onBack }: BackupProps) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        maxWidth: 480,
        margin: '0 auto',
        width: '100%',
        gap: 32,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {onBack && (
          <button
            onClick={onBack}
            style={{
              background: 'none',
              border: 'none',
              fontSize: 24,
              color: 'var(--accent)',
              cursor: 'pointer',
              padding: '8px 12px 8px 0',
              minWidth: 44,
              minHeight: 44,
              display: 'flex',
              alignItems: 'center',
              WebkitTapHighlightColor: 'transparent',
            }}
            aria-label="Back"
          >
            &#8592;
          </button>
        )}
        <h1
          style={{
            fontSize: 24,
            fontWeight: 700,
            color: 'var(--text-primary)',
            margin: 0,
          }}
        >
          Backup &amp; Recovery
        </h1>
      </div>

      <CreateShares identity={identity} />

      {/* Divider */}
      <div
        style={{
          height: 1,
          background: 'var(--border)',
          width: '100%',
        }}
      />

      <RestoreFromShares />
    </div>
  );
}
