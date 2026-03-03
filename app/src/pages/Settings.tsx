import { useState, useCallback, useRef, useEffect } from 'react';
import type { StoredIdentity, StoredConnection, StoredPreferences } from '../lib/db';
import { getConnections } from '../lib/db';
import { ThemeToggle } from '../components/ThemeToggle';
import type { RelayState } from 'signet-protocol';

interface RelayHook {
  state: RelayState;
  url: string;
  connect: () => Promise<void>;
  disconnect: () => void;
  changeUrl: (url: string) => void;
}

interface SettingsProps {
  identity: StoredIdentity;
  identities: StoredIdentity[];
  preferences: StoredPreferences;
  connections: StoredConnection[];
  relay?: RelayHook;
  onSetTheme: (theme: 'system' | 'light' | 'dark') => void;
  onChangeRole: (role: StoredIdentity['role']) => void;
  onDeleteIdentity: () => void;
  onNavigate?: (page: string) => void;
  onSwitchAccount?: (pubkey: string) => void;
  onAddAccount?: () => void;
}

const roleOptions: { value: StoredIdentity['role']; label: string }[] = [
  { value: 'adult', label: 'Adult' },
  { value: 'child', label: 'Child' },
  { value: 'verifier', label: 'Verifier' },
];

const sectionHeaderStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: 1,
  textTransform: 'uppercase',
  color: 'var(--text-secondary)',
  marginBottom: 10,
};

const sectionStyle: React.CSSProperties = {
  marginBottom: 28,
};

interface CertPlatform {
  key: string;
  title: string;
  steps: string[];
}

const certPlatforms: CertPlatform[] = [
  {
    key: 'ios',
    title: 'iOS Safari',
    steps: [
      '1. Download the .pem file above.',
      '2. Go to Settings \u2192 General \u2192 VPN & Device Management.',
      '3. Install the certificate profile.',
      '4. Go to Settings \u2192 General \u2192 About \u2192 Certificate Trust Settings \u2192 enable the Signet certificate.',
    ],
  },
  {
    key: 'android',
    title: 'Android Chrome',
    steps: [
      '1. Download the .pem file above.',
      '2. Go to Settings \u2192 Security \u2192 Encryption & credentials \u2192 Install from storage.',
      '3. Select the file and install as a CA certificate.',
    ],
  },
  {
    key: 'macos',
    title: 'macOS Safari',
    steps: [
      '1. Download the .pem file above.',
      "2. Double-click to open in Keychain Access.",
      "3. Find 'Signet Local Dev', double-click \u2192 Trust \u2192 set 'Always Trust'.",
    ],
  },
  {
    key: 'firefox',
    title: 'Firefox (all platforms)',
    steps: [
      '1. Go to Settings \u2192 Privacy & Security \u2192 View Certificates \u2192 Authorities \u2192 Import.',
      '2. Select the .pem file and trust for websites.',
    ],
  },
];

interface ImportPreview {
  identityName: string | null;
  connectionCount: number;
  hasPreferences: boolean;
  raw: unknown;
}

export function Settings({
  identity,
  identities,
  preferences,
  connections,
  relay,
  onSetTheme,
  onChangeRole,
  onDeleteIdentity,
  onNavigate,
  onSwitchAccount,
  onAddAccount,
}: SettingsProps) {
  const [relayUrlInput, setRelayUrlInput] = useState(relay?.url ?? 'ws://localhost:7777');
  const [relayConnecting, setRelayConnecting] = useState(false);

  useEffect(() => {
    if (relay) setRelayUrlInput(relay.url);
  }, [relay?.url]);

  const handleRelayConnect = useCallback(async () => {
    if (!relay) return;
    setRelayConnecting(true);
    try {
      if (relayUrlInput !== relay.url) {
        relay.changeUrl(relayUrlInput);
      }
      await relay.connect();
    } catch {
      // Ignore - state will show error
    }
    setRelayConnecting(false);
  }, [relay, relayUrlInput]);

  const handleRelayDisconnect = useCallback(() => {
    relay?.disconnect();
  }, [relay]);
  const [showRoleSelector, setShowRoleSelector] = useState(false);
  const [expandedPlatform, setExpandedPlatform] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState(false);
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ── Export ──

  const handleExport = useCallback(async () => {
    try {
      const allConnections = await getConnections();
      const backup = {
        version: 1,
        exportedAt: Date.now(),
        identity,
        connections: allConnections,
        preferences,
      };
      const blob = new Blob([JSON.stringify(backup, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'signet-backup.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      alert('Failed to export data.');
    }
  }, [identity, preferences]);

  // ── Import ──

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    setImportPreview(null);

    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const text = reader.result as string;
        const data = JSON.parse(text);

        if (typeof data !== 'object' || data === null) {
          setImportError('Invalid backup file: not a JSON object.');
          return;
        }

        if (typeof data.version !== 'number') {
          setImportError('Invalid backup file: missing version field.');
          return;
        }

        const preview: ImportPreview = {
          identityName: data.identity?.displayName ?? null,
          connectionCount: Array.isArray(data.connections) ? data.connections.length : 0,
          hasPreferences: !!data.preferences,
          raw: data,
        };

        setImportPreview(preview);
      } catch {
        setImportError('Failed to parse JSON file.');
      }
    };
    reader.onerror = () => {
      setImportError('Failed to read file.');
    };
    reader.readAsText(file);
  }, []);

  const handleClearImport = useCallback(() => {
    setImportPreview(null);
    setImportError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }, []);

  // ── Role Change ──

  const handleRoleChange = useCallback(
    (role: StoredIdentity['role']) => {
      onChangeRole(role);
      setShowRoleSelector(false);
    },
    [onChangeRole],
  );

  // ── Delete ──

  const handleDeleteClick = useCallback(() => {
    if (deleteConfirm) {
      onDeleteIdentity();
    } else {
      setDeleteConfirm(true);
    }
  }, [deleteConfirm, onDeleteIdentity]);

  const handleDeleteCancel = useCallback(() => {
    setDeleteConfirm(false);
  }, []);

  // ── Accordion Toggle ──

  const togglePlatform = useCallback((key: string) => {
    setExpandedPlatform((prev) => (prev === key ? null : key));
  }, []);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        maxWidth: 480,
        margin: '0 auto',
        width: '100%',
        padding: '0 0 32px 0',
      }}
    >
      {/* ── Section 1: Theme ── */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>Theme</div>
        <ThemeToggle current={preferences.theme} onChange={onSetTheme} />
      </div>

      {/* ── Section: Accounts ── */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>Accounts</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
          {identities.map((id) => {
            const isActive = id.publicKey === identity.publicKey;
            return (
              <button
                key={id.publicKey}
                onClick={() => onSwitchAccount?.(id.publicKey)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '10px 14px',
                  background: isActive ? 'var(--bg-input)' : 'var(--bg-card)',
                  border: `1px solid ${isActive ? 'var(--accent)' : 'var(--border)'}`,
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  minHeight: 44,
                  WebkitTapHighlightColor: 'transparent',
                  width: '100%',
                  textAlign: 'left',
                }}
              >
                <span style={{
                  width: 28, height: 28, borderRadius: '50%',
                  background: isActive ? 'var(--accent)' : 'var(--border)',
                  color: isActive ? 'var(--accent-text)' : 'var(--text-secondary)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 13, fontWeight: 700, flexShrink: 0,
                }}>
                  {id.displayName.charAt(0).toUpperCase()}
                </span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
                    {id.displayName}
                    {id.importMethod === 'nsec' ? ' (nsec)' : ''}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                    {id.publicKey.slice(0, 8)}...{id.publicKey.slice(-4)}
                  </div>
                </div>
                {isActive && <span style={{ color: 'var(--accent)', fontSize: 14 }}>&#10003;</span>}
              </button>
            );
          })}
        </div>
        <button
          className="btn btn-secondary"
          onClick={onAddAccount}
          style={{ minHeight: 44 }}
        >
          Add Account
        </button>
        {identities.length >= 2 && (
          <button
            className="btn btn-secondary"
            onClick={() => onNavigate?.('link-accounts')}
            style={{ minHeight: 44, marginTop: 8 }}
          >
            Link Accounts (Identity Bridge)
          </button>
        )}
      </div>

      {/* ── Section: Relay ── */}
      {relay && (
        <div style={sectionStyle}>
          <div style={sectionHeaderStyle}>Relay</div>
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span
                style={{
                  width: 8, height: 8, borderRadius: '50%',
                  background: relay.state === 'connected' ? 'var(--success)' : relay.state === 'connecting' ? 'var(--warning)' : 'var(--danger)',
                  flexShrink: 0,
                }}
              />
              <span style={{ fontSize: 13, color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                {relay.state}
              </span>
            </div>
            <input
              className="input"
              type="text"
              value={relayUrlInput}
              onChange={(e) => setRelayUrlInput(e.target.value)}
              placeholder="ws://localhost:7777"
              style={{ width: '100%', fontFamily: 'monospace', fontSize: 13, marginBottom: 8 }}
            />
            <div style={{ display: 'flex', gap: 8 }}>
              {relay.state !== 'connected' ? (
                <button
                  className="btn btn-primary"
                  style={{ minHeight: 44, flex: 1 }}
                  onClick={handleRelayConnect}
                  disabled={relayConnecting}
                >
                  {relayConnecting ? 'Connecting...' : 'Connect'}
                </button>
              ) : (
                <button
                  className="btn btn-secondary"
                  style={{ minHeight: 44, flex: 1 }}
                  onClick={handleRelayDisconnect}
                >
                  Disconnect
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Section 2: Account Type ── */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>Account Type</div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            marginBottom: 12,
          }}
        >
          <span
            style={{
              display: 'inline-block',
              padding: '4px 14px',
              borderRadius: 999,
              fontSize: 13,
              fontWeight: 600,
              letterSpacing: 0.3,
              textTransform: 'uppercase',
              background: 'var(--accent)',
              color: 'var(--accent-text)',
            }}
          >
            {identity.role}
          </span>
          <span style={{ fontSize: 14, color: 'var(--text-muted)' }}>
            {identity.displayName}
          </span>
        </div>

        {!showRoleSelector ? (
          <button
            className="btn btn-secondary"
            onClick={() => setShowRoleSelector(true)}
            style={{ minHeight: 44 }}
          >
            Change role
          </button>
        ) : (
          <div
            style={{
              display: 'flex',
              borderRadius: 999,
              overflow: 'hidden',
              border: '1px solid var(--border)',
              background: 'var(--bg-input)',
            }}
            role="radiogroup"
            aria-label="Role selection"
          >
            {roleOptions.map((opt) => {
              const isActive = identity.role === opt.value;
              return (
                <button
                  key={opt.value}
                  onClick={() => handleRoleChange(opt.value)}
                  role="radio"
                  aria-checked={isActive}
                  style={{
                    flex: 1,
                    height: 44,
                    border: 'none',
                    cursor: 'pointer',
                    fontSize: 14,
                    fontWeight: isActive ? 600 : 400,
                    background: isActive ? 'var(--accent)' : 'var(--bg-input)',
                    color: isActive ? 'var(--accent-text)' : 'var(--text-secondary)',
                    transition: 'background 0.15s, color 0.15s',
                    WebkitTapHighlightColor: 'transparent',
                    padding: '0 12px',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Section 3: Certificate ── */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>Certificate</div>
        <a
          href="/signet.pem"
          download="signet.pem"
          className="btn btn-secondary"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            minHeight: 44,
            textDecoration: 'none',
            marginBottom: 16,
          }}
        >
          Download Certificate
        </a>

        <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 10 }}>
          Installation instructions (tap to expand):
        </div>

        {certPlatforms.map((platform) => {
          const isOpen = expandedPlatform === platform.key;
          return (
            <div
              key={platform.key}
              style={{
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                marginBottom: 6,
                overflow: 'hidden',
              }}
            >
              <button
                onClick={() => togglePlatform(platform.key)}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px 14px',
                  background: 'var(--bg-card)',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: 14,
                  fontWeight: 500,
                  color: 'var(--text-primary)',
                  minHeight: 44,
                  WebkitTapHighlightColor: 'transparent',
                }}
                aria-expanded={isOpen}
              >
                <span>{platform.title}</span>
                <span
                  style={{
                    fontSize: 12,
                    color: 'var(--text-muted)',
                    transform: isOpen ? 'rotate(90deg)' : 'rotate(0deg)',
                    transition: 'transform 0.15s',
                  }}
                >
                  &#8250;
                </span>
              </button>
              {isOpen && (
                <div
                  style={{
                    padding: '8px 14px 14px',
                    background: 'var(--bg-secondary)',
                    borderTop: '1px solid var(--border-subtle)',
                  }}
                >
                  {platform.steps.map((step, i) => (
                    <p
                      key={i}
                      style={{
                        fontSize: 13,
                        color: 'var(--text-secondary)',
                        lineHeight: 1.5,
                        margin: i === 0 ? 0 : '6px 0 0 0',
                      }}
                    >
                      {step}
                    </p>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Section 4: Shamir Backup ── */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>Recovery Backup</div>
        {identity.importMethod === 'nsec' ? (
          <p
            style={{
              fontSize: 13,
              color: 'var(--warning)',
              marginBottom: 10,
              lineHeight: 1.5,
            }}
          >
            nsec-imported accounts cannot use Shamir backup. Back up your nsec key separately.
          </p>
        ) : (
          <>
            <p
              style={{
                fontSize: 13,
                color: 'var(--text-muted)',
                marginBottom: 10,
                lineHeight: 1.5,
              }}
            >
              Split your recovery phrase into shares using Shamir's Secret Sharing. Distribute to trusted people.
            </p>
            <button
              className="btn btn-secondary"
              onClick={() => onNavigate?.('backup')}
              style={{ minHeight: 44 }}
            >
              Manage Backup Shares
            </button>
          </>
        )}
      </div>

      {/* ── Section 5: Export Data ── */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>Export Data</div>
        <p
          style={{
            fontSize: 13,
            color: 'var(--text-muted)',
            marginBottom: 10,
            lineHeight: 1.5,
          }}
        >
          Download a backup of your identity, connections, and preferences.
        </p>
        <button
          className="btn btn-secondary"
          onClick={handleExport}
          style={{ minHeight: 44 }}
        >
          Export Data
        </button>
      </div>

      {/* ── Section 5: Import Data ── */}
      <div style={sectionStyle}>
        <div style={sectionHeaderStyle}>Import Data</div>
        <p
          style={{
            fontSize: 13,
            color: 'var(--text-muted)',
            marginBottom: 10,
            lineHeight: 1.5,
          }}
        >
          Restore from a previously exported backup file.
        </p>
        <input
          ref={fileInputRef}
          type="file"
          accept=".json"
          onChange={handleFileSelect}
          style={{
            fontSize: 14,
            color: 'var(--text-primary)',
            marginBottom: 12,
            width: '100%',
          }}
        />

        {importError && (
          <div
            style={{
              padding: '10px 14px',
              background: 'var(--danger)',
              color: '#fff',
              borderRadius: 'var(--radius-sm)',
              fontSize: 13,
              marginBottom: 10,
            }}
          >
            {importError}
          </div>
        )}

        {importPreview && (
          <div
            className="card"
            style={{
              padding: 16,
              marginBottom: 10,
            }}
          >
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>
              Backup Preview
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {importPreview.identityName && (
                <div>Identity: {importPreview.identityName}</div>
              )}
              <div>Connections: {importPreview.connectionCount}</div>
              <div>Preferences: {importPreview.hasPreferences ? 'Yes' : 'No'}</div>
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button
                className="btn btn-primary"
                style={{ minHeight: 40, flex: 1 }}
                onClick={() => {
                  alert('Import is not yet implemented. Merging logic requires further development.');
                }}
              >
                Import
              </button>
              <button
                className="btn btn-secondary"
                style={{ minHeight: 40 }}
                onClick={handleClearImport}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Section 6: Danger Zone ── */}
      <div
        style={{
          ...sectionStyle,
          border: '1px solid var(--danger)',
          borderRadius: 'var(--radius)',
          padding: 16,
        }}
      >
        <div style={{ ...sectionHeaderStyle, color: 'var(--danger)' }}>Danger Zone</div>
        <p
          style={{
            fontSize: 13,
            color: 'var(--text-muted)',
            marginBottom: 12,
            lineHeight: 1.5,
          }}
        >
          Deleting your identity is permanent. Your keys, connections, and all local data will be erased.
        </p>
        {deleteConfirm ? (
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn btn-danger"
              onClick={handleDeleteClick}
              style={{ minHeight: 44, flex: 1 }}
            >
              Yes, delete everything
            </button>
            <button
              className="btn btn-secondary"
              onClick={handleDeleteCancel}
              style={{ minHeight: 44 }}
            >
              Cancel
            </button>
          </div>
        ) : (
          <button
            className="btn btn-danger"
            onClick={handleDeleteClick}
            style={{ minHeight: 44 }}
          >
            Delete Identity
          </button>
        )}
      </div>
    </div>
  );
}
