import type { FamilyMember as FamilyMemberType } from '../types';
import { StatusBadge } from '../components/StatusBadge';

interface Props {
  members: FamilyMemberType[];
  onSelectMember: (pubkey: string) => void;
}

export function Family({ members, onSelectMember }: Props) {
  if (members.length === 0) {
    return (
      <div className="fade-in" role="main" style={{ textAlign: 'center', paddingTop: 64 }}>
        <h2 style={{ marginBottom: 8 }}>No family members yet</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
          Tap the + button to add someone and verify it's really them.
        </p>
      </div>
    );
  }

  return (
    <div className="fade-in" role="main">
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {members.map((member, i) => (
          <button
            key={member.pubkey}
            onClick={() => onSelectMember(member.pubkey)}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              width: '100%',
              padding: '14px 16px',
              background: 'none',
              border: 'none',
              borderBottom: i < members.length - 1 ? '1px solid var(--border)' : 'none',
              cursor: 'pointer',
              textAlign: 'left',
              color: 'var(--text-primary)',
            }}
          >
            <div>
              <div style={{ fontWeight: 600, marginBottom: 2 }}>{member.displayName}</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Verified {new Date(member.verifiedAt * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}
              </div>
            </div>
            <StatusBadge isVerified={true} isChild={member.isChild} />
          </button>
        ))}
      </div>

      <p style={{ textAlign: 'center', marginTop: 24, fontSize: '0.85rem', color: 'var(--text-muted)' }}>
        Use "Signet Me" to verify each other in real time.
      </p>
    </div>
  );
}
