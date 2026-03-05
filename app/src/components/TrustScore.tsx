interface TrustScoreProps {
  score: number; // 0-200 (Signet IQ)
  showBreakdown?: boolean;
}

function getScoreColor(score: number): string {
  if (score < 50) return 'var(--danger)';
  if (score < 100) return 'var(--warning)';
  return 'var(--accent)';
}

export function TrustScore({ score, showBreakdown = false }: TrustScoreProps) {
  const clampedScore = Math.max(0, Math.min(200, score));
  const barColor = getScoreColor(clampedScore);

  return (
    <div style={{ width: '100%' }}>
      {/* Score bar row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}
      >
        {/* Track */}
        <div
          style={{
            flex: 1,
            height: 8,
            borderRadius: 4,
            background: 'var(--bg-input)',
            overflow: 'hidden',
          }}
        >
          {/* Fill */}
          <div
            style={{
              width: `${(clampedScore / 200) * 100}%`,
              height: '100%',
              borderRadius: 4,
              background: barColor,
              transition: 'width 0.3s ease, background 0.3s ease',
            }}
          />
        </div>

        {/* Score text */}
        <span
          style={{
            fontSize: 14,
            fontWeight: 600,
            color: barColor,
            minWidth: 40,
            textAlign: 'right',
          }}
        >
          {clampedScore}
        </span>
      </div>

      {/* Label */}
      <div
        style={{
          marginTop: 4,
          fontSize: 12,
          color: 'var(--text-muted)',
        }}
      >
        Signet IQ
      </div>

      {/* Optional breakdown */}
      {showBreakdown && (
        <div
          style={{
            marginTop: 8,
            fontSize: 12,
            color: 'var(--text-secondary)',
            lineHeight: 1.6,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Verification tier</span>
            <span style={{ color: 'var(--text-muted)' }}>--</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Vouches received</span>
            <span style={{ color: 'var(--text-muted)' }}>0</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Connection age</span>
            <span style={{ color: 'var(--text-muted)' }}>--</span>
          </div>
        </div>
      )}
    </div>
  );
}
