import type { FamilyMember as FamilyMemberType, SignetIdentity } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { SignetWords } from '../components/SignetWords';
import { getActivePubkey } from '../lib/signet';
import { useState } from 'react';

interface Props {
  member: FamilyMemberType;
  identity: SignetIdentity;
  onRemove: (pubkey: string) => void;
  wordCount?: number;
}

export function FamilyMemberDetail({ member, identity, onRemove, wordCount }: Props) {
  const [confirmRemove, setConfirmRemove] = useState(false);

  return (
    <div className="fade-in">
      {/* Member info — compact */}
      <div className="card section" style={{ textAlign: 'center' }}>
        <h1 style={{ marginBottom: 4 }}>{member.displayName}</h1>
        <StatusBadge isVerified={true} isChild={member.isChild} />
        <div style={{ marginTop: 8, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Connected {new Date(member.verifiedAt * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}
        </div>
      </div>

      {/* Signet Me — directional verification */}
      <SignetWords
        sharedSecret={member.sharedSecret}
        myPubkey={getActivePubkey(identity)}
        theirPubkey={member.pubkey}
        wordCount={wordCount}
      />

      {/* Remove */}
      <div style={{ marginTop: 32 }}>
        {!confirmRemove ? (
          <button className="btn btn-ghost" onClick={() => setConfirmRemove(true)} style={{ color: 'var(--danger)' }}>
            Remove from family
          </button>
        ) : (
          <div className="card" style={{ borderColor: 'var(--danger)' }}>
            <p style={{ marginBottom: 12, fontSize: '0.9rem' }}>
              Remove {member.displayName} from your family? You'll need to scan their QR code again to reconnect.
            </p>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-danger" onClick={() => onRemove(member.pubkey)} style={{ flex: 1 }}>Remove</button>
              <button className="btn btn-secondary" onClick={() => setConfirmRemove(false)} style={{ flex: 1 }}>Cancel</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
