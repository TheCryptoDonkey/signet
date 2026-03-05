interface Props {
  score: number;
  label?: string;
}

export function TrustBar({ score, label }: Props) {
  const color = score >= 100 ? 'var(--success)' : score >= 50 ? 'var(--warning)' : 'var(--danger)';

  return (
    <div>
      {label && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{label}</span>
          <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>{score}</span>
        </div>
      )}
      <div className="trust-bar">
        <div className="trust-bar-fill" style={{ width: `${(Math.min(score, 200) / 200) * 100}%`, background: color }} />
      </div>
    </div>
  );
}
