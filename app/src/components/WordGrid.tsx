import { useState, useEffect, useCallback, useMemo } from 'react';
import { SIGNET_WORDLIST } from 'signet-protocol';

interface WordGridProps {
  words: string[];
  mode: 'display' | 'verify';
  onVerified?: () => void;
  onFailed?: () => void;
}

/** Pick `count` unique random indices from 0..max-1 */
function pickRandom(max: number, count: number): number[] {
  const indices = new Set<number>();
  while (indices.size < count) {
    indices.add(Math.floor(Math.random() * max));
  }
  return Array.from(indices);
}

/** Shuffle an array (Fisher-Yates) */
function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/** Pick random BIP-39 words that aren't in `exclude` */
function randomDecoys(exclude: Set<string>, count: number): string[] {
  const decoys: string[] = [];
  const tried = new Set<number>();
  while (decoys.length < count && tried.size < SIGNET_WORDLIST.length) {
    const idx = Math.floor(Math.random() * SIGNET_WORDLIST.length);
    if (tried.has(idx)) continue;
    tried.add(idx);
    const w = SIGNET_WORDLIST[idx];
    if (!exclude.has(w)) {
      decoys.push(w);
    }
  }
  return decoys;
}

// ─── Display Mode ───────────────────────────────────────────────

function DisplayGrid({ words }: { words: string[] }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gap: 10,
        width: '100%',
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
            padding: '10px 12px',
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
              fontSize: 14,
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
  );
}

// ─── Verify Mode ────────────────────────────────────────────────

interface VerifyState {
  positions: number[];       // 3 word indices to verify
  currentStep: number;       // 0, 1, or 2
  options: string[][];       // shuffled option arrays per step
}

function VerifyGrid({
  words,
  onVerified,
  onFailed,
}: {
  words: string[];
  onVerified?: () => void;
  onFailed?: () => void;
}) {
  const wordSet = useMemo(() => new Set(words), [words]);

  const [state, setState] = useState<VerifyState | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [result, setResult] = useState<'correct' | 'wrong' | null>(null);

  // Initialize verification challenge
  useEffect(() => {
    const positions = pickRandom(words.length, 3).sort((a, b) => a - b);
    const options = positions.map((pos) => {
      const correct = words[pos];
      const decoys = randomDecoys(wordSet, 7);
      return shuffle([correct, ...decoys]);
    });
    setState({ positions, currentStep: 0, options });
    setSelected(null);
    setResult(null);
  }, [words, wordSet]);

  const handleSelect = useCallback(
    (word: string) => {
      if (!state || result !== null) return;

      const { positions, currentStep } = state;
      const correctWord = words[positions[currentStep]];
      setSelected(word);

      if (word === correctWord) {
        setResult('correct');
        setTimeout(() => {
          const nextStep = currentStep + 1;
          if (nextStep >= 3) {
            onVerified?.();
          } else {
            setState((prev) => prev ? { ...prev, currentStep: nextStep } : prev);
            setSelected(null);
            setResult(null);
          }
        }, 600);
      } else {
        setResult('wrong');
        setTimeout(() => {
          onFailed?.();
        }, 800);
      }
    },
    [state, result, words, onVerified, onFailed],
  );

  if (!state) return null;

  const { positions, currentStep, options } = state;
  const currentPos = positions[currentStep];
  const currentOptions = options[currentStep];

  return (
    <div style={{ width: '100%' }}>
      {/* Progress dots */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          gap: 8,
          marginBottom: 16,
        }}
      >
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background:
                i < currentStep
                  ? 'var(--success)'
                  : i === currentStep
                    ? 'var(--accent)'
                    : 'var(--border)',
              transition: 'background 0.2s',
            }}
          />
        ))}
      </div>

      <p
        style={{
          textAlign: 'center',
          fontSize: 16,
          fontWeight: 600,
          color: 'var(--text-primary)',
          marginBottom: 20,
        }}
      >
        Select word #{currentPos + 1}
      </p>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: 10,
        }}
      >
        {currentOptions.map((word) => {
          const isSelected = selected === word;
          let bg = 'var(--bg-input)';
          let borderColor = 'var(--border-subtle)';
          let textColor = 'var(--text-primary)';

          if (isSelected && result === 'correct') {
            bg = 'var(--success)';
            borderColor = 'var(--success)';
            textColor = '#ffffff';
          } else if (isSelected && result === 'wrong') {
            bg = 'var(--danger)';
            borderColor = 'var(--danger)';
            textColor = '#ffffff';
          }

          return (
            <button
              key={word}
              onClick={() => handleSelect(word)}
              disabled={result !== null}
              style={{
                background: bg,
                border: `1px solid ${borderColor}`,
                borderRadius: 'var(--radius-sm)',
                padding: '12px 8px',
                fontSize: 14,
                fontWeight: 500,
                fontFamily: 'monospace',
                color: textColor,
                cursor: result !== null ? 'default' : 'pointer',
                transition: 'background 0.15s, border-color 0.15s, color 0.15s',
                minHeight: 44,
                WebkitTapHighlightColor: 'transparent',
              }}
            >
              {word}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ─── Export ──────────────────────────────────────────────────────

export function WordGrid({ words, mode, onVerified, onFailed }: WordGridProps) {
  if (mode === 'display') {
    return <DisplayGrid words={words} />;
  }
  return <VerifyGrid words={words} onVerified={onVerified} onFailed={onFailed} />;
}
