import { useState, useEffect, useCallback } from 'react';
import type { SignetIdentity, ChildSettings as ChildSettingsType } from '../types';
import { getActiveDisplayName } from '../lib/signet';
import * as db from '../lib/db';

interface Props {
  identity: SignetIdentity;
  childIdentities: SignetIdentity[];
}

export function ChildSettingsPage({ identity, childIdentities }: Props) {
  const [settings, setSettings] = useState<Map<string, ChildSettingsType>>(new Map());

  const loadSettings = useCallback(async () => {
    const map = new Map<string, ChildSettingsType>();
    for (const child of childIdentities) {
      const s = await db.getChildSettings(child.id);
      map.set(child.id, s || {
        childPubkey: child.id,
        guardianPubkey: identity.id,
        contactPolicy: 'family-only',
      });
    }
    setSettings(map);
  }, [childIdentities, identity.id]);

  useEffect(() => { loadSettings(); }, [loadSettings]);

  const updatePolicy = async (childPubkey: string, policy: 'family-only' | 'approved' | 'open') => {
    const existing = settings.get(childPubkey);
    const updated: ChildSettingsType = {
      ...existing!,
      contactPolicy: policy,
    };
    await db.saveChildSettings(updated);
    setSettings(prev => new Map(prev).set(childPubkey, updated));
  };

  if (childIdentities.length === 0) {
    return (
      <div className="fade-in" style={{ textAlign: 'center', paddingTop: 64 }}>
        <h2 style={{ marginBottom: 8 }}>No child accounts</h2>
        <p style={{ color: 'var(--text-secondary)' }}>
          Create a child account to manage their settings here.
        </p>
      </div>
    );
  }

  return (
    <div className="fade-in">
      {childIdentities.map(child => {
        const s = settings.get(child.id);
        return (
          <div key={child.id} className="card section">
            <h3 style={{ marginBottom: 4 }}>{getActiveDisplayName(child)}</h3>
            <div className="section-title">Who can contact {getActiveDisplayName(child)}?</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {(['family-only', 'approved', 'open'] as const).map(policy => (
                <label key={policy} style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 12px', borderRadius: 'var(--radius-sm)',
                  border: s?.contactPolicy === policy ? '2px solid var(--accent)' : '1px solid var(--border)',
                  cursor: 'pointer',
                }}>
                  <input
                    type="radio"
                    name={`policy-${child.id}`}
                    checked={s?.contactPolicy === policy}
                    onChange={() => updatePolicy(child.id, policy)}
                  />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                      {policy === 'family-only' && 'Family only'}
                      {policy === 'approved' && 'Approved contacts'}
                      {policy === 'open' && 'Open'}
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {policy === 'family-only' && 'Can only connect with people you\'ve verified'}
                      {policy === 'approved' && 'You must approve each new connection'}
                      {policy === 'open' && 'Anyone can connect (not recommended for under-13s)'}
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
