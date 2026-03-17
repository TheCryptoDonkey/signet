import { useState, useCallback, useEffect, useRef } from 'react';
import type { Page } from './types';
import type { StoredCredential } from './types';
import { useIdentity } from './hooks/useIdentity';
import { useFamily } from './hooks/useFamily';
import { usePreferences } from './hooks/usePreferences';
import { useDocuments } from './hooks/useDocuments';
import { useCredentials } from './hooks/useCredentials';
import { Layout } from './components/Layout';
import { Onboarding } from './pages/Onboarding';
import { Home } from './pages/Home';
import { Family } from './pages/Family';
import { FamilyMemberDetail } from './pages/FamilyMember';
import { AddMember } from './pages/AddMember';
import { Settings } from './pages/Settings';
import { ChildSettingsPage } from './pages/ChildSettings';
import { GetVerified } from './pages/GetVerified';
import { MyDocuments } from './pages/MyDocuments';
import { VerifySomeone } from './pages/VerifySomeone';
import { ShamirBackup } from './pages/ShamirBackup';
import { IdentityBridge } from './pages/IdentityBridge';
import { CredentialDetail } from './pages/CredentialDetail';
import { ApproveVerification } from './pages/ApproveVerification';
import { ApproveConnect } from './pages/ApproveConnect';
import { AuthScreen } from './pages/AuthScreen';
import { SetupAuth } from './pages/SetupAuth';
import { getActivePubkey, getActivePrivateKey, getActiveDisplayName } from './lib/signet';
import { isAuthSetUp, generateEncryptionKey, clearAuthData } from './lib/auth';
import type { VerifyRequest, VerifyResponse } from './lib/presentation';
import { buildVerifyResponse, sendResponseViaBroadcast, parseVerifyRequest } from './lib/presentation';
import { parseNostrConnectURI } from './lib/nip46';
import type { NostrConnectRequest } from './lib/nip46';

const INACTIVITY_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

export function App() {
  // Auth state (must be declared before hooks that depend on encryptionKey)
  const [encryptionKey, setEncryptionKey] = useState<string | null>(null);
  const [pendingEncryptionKey, setPendingEncryptionKey] = useState<string | null>(null);
  const inactivityTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { identity, identities, loading: identityLoading, create, restore, importNsec, remove, markBackedUp, switchPrimary } = useIdentity(encryptionKey);
  const { members, addMember, removeMember } = useFamily(identity?.id, encryptionKey);
  const { preferences, loading: prefsLoading, setTheme, securityTier, wordCount, setSecurityTier } = usePreferences();
  const activePubkey = identity ? getActivePubkey(identity) : undefined;
  const { documents } = useDocuments(activePubkey);
  const { credentials } = useCredentials();

  const [page, setPage] = useState<Page>('home');
  const [selectedMemberPubkey, setSelectedMemberPubkey] = useState<string | null>(null);
  const [selectedCredential, setSelectedCredential] = useState<StoredCredential | null>(null);
  const [powerMode, setPowerMode] = useState(false);
  const [pendingVerifyRequest, setPendingVerifyRequest] = useState<VerifyRequest | null>(null);
  const [pendingConnectRequest, setPendingConnectRequest] = useState<NostrConnectRequest | null>(null);

  // Reset inactivity timer on user activity
  const resetInactivityTimer = useCallback(() => {
    if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
    inactivityTimer.current = setTimeout(() => {
      setEncryptionKey(null); // lock the app
    }, INACTIVITY_TIMEOUT_MS);
  }, []);

  // Upgrade path: existing account without auth — trigger setup once
  useEffect(() => {
    if (!identityLoading && !prefsLoading && identity && !isAuthSetUp() && !pendingEncryptionKey && !encryptionKey) {
      setPendingEncryptionKey(generateEncryptionKey());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identityLoading, prefsLoading, identity?.id]);

  // Attach activity listeners when authenticated
  useEffect(() => {
    if (!encryptionKey) return;

    const events = ['mousedown', 'mousemove', 'keydown', 'touchstart', 'scroll'] as const;
    const handler = () => resetInactivityTimer();

    events.forEach(ev => window.addEventListener(ev, handler, { passive: true }));
    resetInactivityTimer(); // start the timer immediately on unlock

    const handleVisibility = () => {
      if (document.visibilityState === 'hidden') setEncryptionKey(null);
    };
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      events.forEach(ev => window.removeEventListener(ev, handler));
      document.removeEventListener('visibilitychange', handleVisibility);
      if (inactivityTimer.current) clearTimeout(inactivityTimer.current);
    };
  }, [encryptionKey, resetInactivityTimer]);

  const handleUnlock = useCallback((key: string) => {
    setEncryptionKey(key);
  }, []);

  const handleSetupComplete = useCallback(() => {
    if (pendingEncryptionKey) {
      setEncryptionKey(pendingEncryptionKey);
      setPendingEncryptionKey(null);
    }
  }, [pendingEncryptionKey]);

  const handleCreate = useCallback(async (displayName: string, primaryKeypair: 'natural-person' | 'persona', isChild: boolean, guardianPubkey?: string) => {
    const key = generateEncryptionKey();
    await create(displayName, primaryKeypair, isChild, guardianPubkey, key);
    setPendingEncryptionKey(key);
  }, [create]);

  const handleImport = useCallback(async (mnemonic: string, displayName: string, primaryKeypair: 'natural-person' | 'persona', isChild: boolean, guardianPubkey?: string) => {
    const key = generateEncryptionKey();
    await restore(mnemonic, displayName, primaryKeypair, isChild, guardianPubkey, key);
    setPendingEncryptionKey(key);
  }, [restore]);

  const handleMarkBackedUp = useCallback(async () => {
    await markBackedUp();
  }, [markBackedUp]);

  const handleSelectMember = useCallback((pubkey: string) => {
    setSelectedMemberPubkey(pubkey);
    setPage('member-detail');
  }, []);

  const handleRemoveMember = useCallback(async (pubkey: string) => {
    await removeMember(pubkey);
    setPage('family');
    setSelectedMemberPubkey(null);
  }, [removeMember]);

  const handleAddDone = useCallback(() => {
    setPage('family');
  }, []);

  const handleImportNsec = useCallback(async (nsec: string, displayName: string, primaryKeypair: 'natural-person' | 'persona') => {
    const key = generateEncryptionKey();
    await importNsec(nsec, displayName, primaryKeypair, key);
    setPendingEncryptionKey(key);
  }, [importNsec]);

  const handleDeleteIdentity = useCallback(async () => {
    await remove();
    clearAuthData();
  }, [remove]);

  const handleApproveVerification = useCallback(() => {
    if (!pendingVerifyRequest) return;
    // Find a persona credential (preferred for age verification — anonymous)
    const personaCred = credentials.find(c => c.keypairType === 'persona');
    const credToUse = personaCred ?? credentials[0] ?? null;
    if (!credToUse) {
      setPendingVerifyRequest(null);
      setPage('home');
      return;
    }
    let parsedEvent: VerifyResponse['credential'] | null = null;
    try {
      const raw: unknown = JSON.parse(credToUse.event);
      if (typeof raw === 'object' && raw !== null) {
        const e = raw as Record<string, unknown>;
        parsedEvent = {
          id: typeof e.id === 'string' ? e.id : credToUse.id,
          kind: typeof e.kind === 'number' ? e.kind : 30470,
          pubkey: typeof e.pubkey === 'string' ? e.pubkey : '',
          tags: Array.isArray(e.tags) ? (e.tags as string[][]) : [],
          content: typeof e.content === 'string' ? e.content : '',
          sig: typeof e.sig === 'string' ? e.sig : '',
          created_at: typeof e.created_at === 'number' ? e.created_at : credToUse.verifiedAt,
        };
      }
    } catch {
      // If event parsing fails, build a minimal object from stored fields
      parsedEvent = {
        id: credToUse.id,
        kind: 30470,
        pubkey: '',
        tags: [],
        content: credToUse.event,
        sig: '',
        created_at: credToUse.verifiedAt,
      };
    }
    if (parsedEvent) {
      const subjectPubkey = activePubkey ?? '';
      const response = buildVerifyResponse(pendingVerifyRequest.requestId, parsedEvent, subjectPubkey);
      sendResponseViaBroadcast(response);
    }
    setPendingVerifyRequest(null);
    setPage('home');
  }, [pendingVerifyRequest, credentials, activePubkey]);

  const handleDenyVerification = useCallback(() => {
    setPendingVerifyRequest(null);
    setPage('home');
  }, []);

  const handleNostrConnect = useCallback((data: string) => {
    const request = parseNostrConnectURI(data);
    if (request) {
      setPendingConnectRequest(request);
      setPage('approve-connect');
    }
  }, []);

  const handleConnectDone = useCallback(() => {
    setPendingConnectRequest(null);
    setPage('home');
  }, []);

  // Listen for same-device verification requests via BroadcastChannel
  useEffect(() => {
    const channel = new BroadcastChannel('signet-verify-request');
    const handleMessage = (event: MessageEvent) => {
      const request = parseVerifyRequest(JSON.stringify(event.data));
      if (!request) return;
      setPendingVerifyRequest(request);
      setPage('approve-verification');
    };
    channel.addEventListener('message', handleMessage);
    return () => {
      channel.removeEventListener('message', handleMessage);
      channel.close();
    };
  }, []);

  // Loading
  if (identityLoading || prefsLoading) {
    return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', color: 'var(--text-secondary)' }}>Loading...</div>;
  }

  // No identity — show onboarding
  if (!identity) {
    return <Onboarding onCreate={handleCreate} onImport={handleImport} onImportNsec={handleImportNsec} />;
  }

  // Identity exists — check auth state

  // Auth is set up but session not yet unlocked — show lock screen
  if (isAuthSetUp() && !encryptionKey && !pendingEncryptionKey) {
    return <AuthScreen onUnlock={handleUnlock} />;
  }

  // New account or existing account without auth yet — show setup
  if (pendingEncryptionKey) {
    return <SetupAuth encryptionKey={pendingEncryptionKey} onComplete={handleSetupComplete} />;
  }

  // Child identities (for parent's child settings)
  const childIdentities = identities.filter(i => i.guardianPubkey === identity.id);

  // Settings page
  if (page === 'settings') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => {}} title="Settings" showBack onBack={() => setPage('home')}>
        <Settings
          identity={identity}
          preferences={preferences}
          securityTier={securityTier}
          onSetTheme={setTheme}
          onSetSecurityTier={setSecurityTier}
          onDeleteIdentity={handleDeleteIdentity}
          onOpenChildSettings={() => setPage('child-settings')}
          hasChildren={childIdentities.length > 0}
          powerMode={powerMode}
          onSetPowerMode={setPowerMode}
          onNavigateShamir={() => setPage('shamir')}
          onNavigateBridge={() => setPage('identity-bridge')}
          onSwitchPrimary={(kp) => switchPrimary(kp)}
        />
      </Layout>
    );
  }

  // Child settings
  if (page === 'child-settings') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => {}} title="Child Accounts" showBack onBack={() => setPage('settings')}>
        <ChildSettingsPage identity={identity} childIdentities={childIdentities} />
      </Layout>
    );
  }

  // Member detail
  if (page === 'member-detail' && selectedMemberPubkey) {
    const member = members.find(m => m.pubkey === selectedMemberPubkey);
    if (!member) { setPage('family'); return null; }
    return (
      <Layout activePage="family" onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title={member.displayName} showBack onBack={() => setPage('family')}>
        <FamilyMemberDetail member={member} identity={identity} onRemove={handleRemoveMember} wordCount={wordCount} />
      </Layout>
    );
  }

  // Add member
  if (page === 'add') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Add Family Member" showBack onBack={() => setPage('home')}>
        <AddMember identity={identity} onAddMember={addMember} onDone={handleAddDone} wordCount={wordCount} onNostrConnect={handleNostrConnect} />
      </Layout>
    );
  }

  // Family list
  if (page === 'family') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="My Family">
        <Family members={members} onSelectMember={handleSelectMember} />
      </Layout>
    );
  }

  // Get Verified
  if (page === 'get-verified') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Get Verified" showBack onBack={() => setPage('home')}>
        <GetVerified identity={identity} onMarkBackedUp={handleMarkBackedUp} />
      </Layout>
    );
  }

  // My Documents
  if (page === 'my-documents') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="My Documents" showBack onBack={() => setPage('home')}>
        <MyDocuments documents={documents} onAddDocument={() => setPage('add-document')} onSelectDocument={() => {}} />
      </Layout>
    );
  }

  // Verify Someone
  if (page === 'verify-someone') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Verify Someone" showBack onBack={() => setPage('home')}>
        <VerifySomeone identity={identity} />
      </Layout>
    );
  }

  // Shamir Backup
  if (page === 'shamir') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Shamir Backup" showBack onBack={() => setPage('settings')}>
        <ShamirBackup identity={identity} onBack={() => setPage('settings')} />
      </Layout>
    );
  }

  // Identity Bridge
  if (page === 'identity-bridge') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Identity Bridge" showBack onBack={() => setPage('settings')}>
        <IdentityBridge identity={identity} onBack={() => setPage('settings')} />
      </Layout>
    );
  }

  // Approve Verification
  if (page === 'approve-verification' && pendingVerifyRequest) {
    const personaCred = credentials.find(c => c.keypairType === 'persona') ?? credentials[0] ?? null;
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Verify Age" showBack onBack={handleDenyVerification}>
        <ApproveVerification
          request={pendingVerifyRequest}
          credential={personaCred}
          onApprove={handleApproveVerification}
          onDeny={handleDenyVerification}
          onNavigateGetVerified={() => { setPendingVerifyRequest(null); setPage('get-verified'); }}
        />
      </Layout>
    );
  }

  // Approve Connect (NIP-46)
  if (page === 'approve-connect' && pendingConnectRequest && identity) {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Connect" showBack onBack={handleConnectDone}>
        <ApproveConnect
          request={pendingConnectRequest}
          signerPrivateKey={getActivePrivateKey(identity)}
          signerPubkey={getActivePubkey(identity)}
          signerDisplayName={getActiveDisplayName(identity)}
          onDone={handleConnectDone}
        />
      </Layout>
    );
  }

  // Credential Detail
  if (page === 'credential-detail' && selectedCredential) {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Credential" showBack onBack={() => { setSelectedCredential(null); setPage('home'); }}>
        <CredentialDetail credential={selectedCredential} onBack={() => { setSelectedCredential(null); setPage('home'); }} />
      </Layout>
    );
  }

  // Home (default) — shows family members front and centre
  return (
    <Layout activePage="home" onNavigate={setPage} onSettingsOpen={() => setPage('settings')}>
      <Home
        identity={identity}
        members={members}
        credentials={credentials}
        onSelectMember={handleSelectMember}
        onNavigateAdd={() => setPage('add')}
        onNavigateGetVerified={() => setPage('get-verified')}
        onNavigateDocuments={() => setPage('my-documents')}
        onSelectCredential={(cred) => { setSelectedCredential(cred); setPage('credential-detail'); }}
      />
    </Layout>
  );
}
