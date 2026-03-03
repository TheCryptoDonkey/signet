import type { ReactNode } from 'react';
import type { StoredIdentity } from '../lib/db';
import { AccountSwitcher } from './AccountSwitcher';

interface LayoutProps {
  activePage: string;
  onNavigate: (page: string) => void;
  role: 'adult' | 'child' | 'verifier';
  identities: StoredIdentity[];
  activeIdentity: StoredIdentity;
  onSwitchAccount: (pubkey: string) => void;
  onAddAccount: () => void;
  children: ReactNode;
}

interface TabDef {
  key: string;
  label: string;
  icon: string;
}

const baseTabs: TabDef[] = [
  { key: 'home', label: 'Home', icon: '\u2302' },
  { key: 'connections', label: 'Connections', icon: '\u{1F465}' },
  { key: 'scan', label: 'Scan', icon: '\u{1F4F7}' },
  { key: 'settings', label: 'Settings', icon: '\u2699' },
];

const verifierTab: TabDef = { key: 'verify', label: 'Verify', icon: '\u{1F6E1}' };

export function Layout({ activePage, onNavigate, role, identities, activeIdentity, onSwitchAccount, onAddAccount, children }: LayoutProps) {
  const tabs = role === 'verifier'
    ? [...baseTabs, verifierTab]
    : baseTabs;

  return (
    <div className="app">
      {/* Header with account switcher */}
      {identities.length > 1 && (
        <header
          style={{
            padding: '8px 16px',
            borderBottom: '1px solid var(--border-subtle)',
            background: 'var(--bg)',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <AccountSwitcher
            identities={identities}
            activeIdentity={activeIdentity}
            onSwitch={onSwitchAccount}
            onAddAccount={onAddAccount}
          />
        </header>
      )}

      <main className="page">
        {children}
      </main>

      <nav
        style={{
          position: 'fixed',
          bottom: 0,
          left: 0,
          right: 0,
          height: 'var(--nav-height)',
          paddingBottom: 'var(--safe-bottom)',
          background: 'var(--bg-card)',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-around',
          zIndex: 100,
          boxShadow: '0 -1px 8px rgba(0,0,0,0.06)',
        }}
      >
        {tabs.map((tab) => {
          const isActive = activePage === tab.key;
          const isScan = tab.key === 'scan';

          return (
            <button
              key={tab.key}
              onClick={() => onNavigate(tab.key)}
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 2,
                background: isScan
                  ? isActive ? 'var(--accent-hover)' : 'var(--accent)'
                  : 'transparent',
                border: 'none',
                borderRadius: isScan ? '50%' : 0,
                width: isScan ? 52 : 48,
                height: isScan ? 52 : 48,
                minWidth: 44,
                minHeight: 44,
                marginTop: isScan ? -14 : 0,
                boxShadow: isScan ? 'var(--shadow-lg)' : 'none',
                cursor: 'pointer',
                color: isScan
                  ? 'var(--accent-text)'
                  : isActive
                    ? 'var(--accent)'
                    : 'var(--text-muted)',
                transition: 'color 0.15s, background 0.15s',
                WebkitTapHighlightColor: 'transparent',
              }}
              aria-label={tab.label}
              aria-current={isActive ? 'page' : undefined}
            >
              <span
                style={{
                  fontSize: isScan ? 22 : 20,
                  lineHeight: 1,
                }}
              >
                {tab.icon}
              </span>
              {!isScan && (
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: isActive ? 600 : 400,
                    letterSpacing: 0.2,
                  }}
                >
                  {tab.label}
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </div>
  );
}
