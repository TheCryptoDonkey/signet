# My Signet Family App — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a hyper-simple, production-ready family app ("My Signet") that lets families create identities, verify each other via QR + Signet Me words, and confirm they're not talking to a deepfake.

**Architecture:** Separate app in the monorepo (`family-app/`), importing `signet-protocol` via path alias. React 19 + Vite 6 + TypeScript. Local-first with IndexedDB (no relay dependency). PWA-ready. Three-tab navigation (My Signet, My Family, Add). Settings behind gear icon.

**Tech Stack:** React 19, Vite 6, TypeScript 5.7, IndexedDB (idb v8), qrcode, html5-qrcode, signet-protocol (path alias to `../src`)

**Design Doc:** `docs/plans/2026-03-05-my-signet-family-app-design.md`

---

## Task 1: Project Scaffolding

**Files:**
- Create: `family-app/package.json`
- Create: `family-app/vite.config.ts`
- Create: `family-app/tsconfig.json`
- Create: `family-app/index.html`
- Create: `family-app/src/main.tsx`
- Create: `family-app/src/App.tsx` (minimal placeholder)

**Step 1: Create package.json**

```json
{
  "name": "my-signet",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite --host",
    "build": "vite build",
    "preview": "vite preview",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "idb": "^8.0.0",
    "qrcode": "^1.5.4",
    "html5-qrcode": "^2.3.8"
  },
  "devDependencies": {
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "@types/qrcode": "^1.5.5",
    "@vitejs/plugin-react": "^4.3.0",
    "typescript": "^5.7.0",
    "vite": "^6.0.0"
  }
}
```

**Step 2: Create vite.config.ts**

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import fs from 'fs';

const certDir = path.resolve(__dirname, '../app/cert');
const hasCerts = fs.existsSync(path.join(certDir, 'signet.pem'));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      'signet-protocol': path.resolve(__dirname, '../src'),
    },
  },
  server: {
    port: 5175,
    ...(hasCerts
      ? {
          https: {
            cert: fs.readFileSync(path.join(certDir, 'signet.pem')),
            key: fs.readFileSync(path.join(certDir, 'signet-key.pem')),
          },
        }
      : {}),
  },
});
```

**Step 3: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "paths": {
      "signet-protocol": ["../src"],
      "signet-protocol/*": ["../src/*"]
    }
  },
  "include": ["src"]
}
```

**Step 4: Create index.html**

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
    <meta name="theme-color" content="#2563EB" media="(prefers-color-scheme: light)" />
    <meta name="theme-color" content="#3B82F6" media="(prefers-color-scheme: dark)" />
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-status-bar-style" content="default" />
    <title>My Signet</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

**Step 5: Create src/main.tsx**

```typescript
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles/global.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
```

**Step 6: Create minimal src/App.tsx placeholder**

```typescript
export function App() {
  return <div>My Signet</div>;
}
```

**Step 7: Install dependencies and verify build**

```bash
cd family-app && npm install && npm run typecheck
```

**Step 8: Commit**

```bash
git add family-app/
git commit -m "feat(family-app): scaffold My Signet project with Vite + React + TypeScript"
```

---

## Task 2: Design System (CSS)

**Files:**
- Create: `family-app/src/styles/global.css`

**Step 1: Write the design system**

```css
/* My Signet — Design System */

/* Reset */
*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

:root {
  /* Light theme (default) */
  --bg-primary: #FFFFFF;
  --bg-secondary: #F8F9FA;
  --bg-card: #FFFFFF;
  --text-primary: #1A1A2E;
  --text-secondary: #6B7280;
  --text-muted: #9CA3AF;
  --accent: #2563EB;
  --accent-hover: #1D4ED8;
  --accent-light: #DBEAFE;
  --success: #059669;
  --success-light: #D1FAE5;
  --warning: #D97706;
  --warning-light: #FEF3C7;
  --danger: #DC2626;
  --danger-light: #FEE2E2;
  --border: #E5E7EB;
  --shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  --shadow-lg: 0 4px 12px rgba(0, 0, 0, 0.1);
  --radius: 12px;
  --radius-sm: 8px;
  --nav-height: 64px;
}

[data-theme="dark"] {
  --bg-primary: #0F172A;
  --bg-secondary: #1E293B;
  --bg-card: #1E293B;
  --text-primary: #F1F5F9;
  --text-secondary: #94A3B8;
  --text-muted: #64748B;
  --accent: #3B82F6;
  --accent-hover: #2563EB;
  --accent-light: #1E3A5F;
  --success: #10B981;
  --success-light: #064E3B;
  --warning: #F59E0B;
  --warning-light: #78350F;
  --danger: #EF4444;
  --danger-light: #7F1D1D;
  --border: #334155;
  --shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
  --shadow-lg: 0 4px 12px rgba(0, 0, 0, 0.4);
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg-primary: #0F172A;
    --bg-secondary: #1E293B;
    --bg-card: #1E293B;
    --text-primary: #F1F5F9;
    --text-secondary: #94A3B8;
    --text-muted: #64748B;
    --accent: #3B82F6;
    --accent-hover: #2563EB;
    --accent-light: #1E3A5F;
    --success: #10B981;
    --success-light: #064E3B;
    --warning: #F59E0B;
    --warning-light: #78350F;
    --danger: #EF4444;
    --danger-light: #7F1D1D;
    --border: #334155;
    --shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    --shadow-lg: 0 4px 12px rgba(0, 0, 0, 0.4);
  }
}

html, body {
  height: 100%;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-size: 16px;
  line-height: 1.5;
  color: var(--text-primary);
  background: var(--bg-primary);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

#root {
  min-height: 100%;
  display: flex;
  flex-direction: column;
}

/* Typography */
h1 { font-size: 1.75rem; font-weight: 700; letter-spacing: -0.02em; }
h2 { font-size: 1.25rem; font-weight: 600; letter-spacing: -0.01em; }
h3 { font-size: 1rem; font-weight: 600; }

/* Cards */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px;
  box-shadow: var(--shadow);
}

/* Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: var(--radius-sm);
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: background 200ms ease, transform 100ms ease;
  width: 100%;
}

.btn:active { transform: scale(0.98); }

.btn-primary {
  background: var(--accent);
  color: #FFFFFF;
}
.btn-primary:hover { background: var(--accent-hover); }

.btn-secondary {
  background: var(--bg-secondary);
  color: var(--text-primary);
  border: 1px solid var(--border);
}

.btn-danger {
  background: var(--danger);
  color: #FFFFFF;
}

.btn-ghost {
  background: transparent;
  color: var(--accent);
  padding: 8px 16px;
}

/* Inputs */
.input {
  width: 100%;
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 1rem;
  background: var(--bg-primary);
  color: var(--text-primary);
  transition: border-color 200ms ease;
}

.input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-light);
}

/* Badge */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: 100px;
  font-size: 0.8rem;
  font-weight: 600;
}

.badge-verified {
  background: var(--success-light);
  color: var(--success);
}

.badge-unverified {
  background: var(--bg-secondary);
  color: var(--text-secondary);
}

.badge-child {
  background: var(--accent-light);
  color: var(--accent);
}

/* Trust bar */
.trust-bar {
  height: 8px;
  background: var(--bg-secondary);
  border-radius: 4px;
  overflow: hidden;
}

.trust-bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 500ms ease;
}

/* Page container */
.page {
  flex: 1;
  padding: 16px;
  padding-bottom: calc(var(--nav-height) + 24px);
  max-width: 480px;
  margin: 0 auto;
  width: 100%;
}

/* Section spacing */
.section { margin-bottom: 24px; }
.section-title {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 8px;
}

/* Signet Words (anti-deepfake) — must be highly readable */
.signet-word {
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
  font-size: 1.5rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  padding: 8px 16px;
  background: var(--accent-light);
  color: var(--accent);
  border-radius: var(--radius-sm);
  text-align: center;
}

/* Fade in animation */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

.fade-in {
  animation: fadeIn 200ms ease forwards;
}

/* Success animation */
@keyframes checkmark {
  0% { transform: scale(0); }
  50% { transform: scale(1.2); }
  100% { transform: scale(1); }
}

.checkmark-anim {
  animation: checkmark 300ms ease forwards;
}
```

**Step 2: Verify CSS loads correctly**

```bash
cd family-app && npm run dev
```
Open https://localhost:5175 — should show "My Signet" with correct font and background.

**Step 3: Commit**

```bash
git add family-app/src/styles/
git commit -m "feat(family-app): add design system with light/dark themes"
```

---

## Task 3: Database Layer

**Files:**
- Create: `family-app/src/types.ts`
- Create: `family-app/src/lib/db.ts`

**Step 1: Write app-specific types**

```typescript
// family-app/src/types.ts
// App-specific types for My Signet family app

export interface FamilyIdentity {
  /** Pubkey — primary key */
  id: string;
  publicKey: string;
  privateKey: string;
  mnemonic: string;
  displayName: string;
  isChild: boolean;
  guardianPubkey?: string;
  ageRange?: string;
  createdAt: number;
}

export interface FamilyMember {
  /** Their pubkey — primary key */
  pubkey: string;
  /** Which of our accounts owns this connection */
  ownerPubkey: string;
  displayName: string;
  /** ECDH shared secret for Signet Me words */
  sharedSecret: string;
  /** When we verified them */
  verifiedAt: number;
  /** Optional relationship label */
  relationship?: 'parent' | 'child' | 'sibling' | 'grandparent' | 'partner' | 'other';
  isChild?: boolean;
}

export interface ChildSettings {
  /** Child's pubkey — primary key */
  childPubkey: string;
  guardianPubkey: string;
  contactPolicy: 'family-only' | 'approved' | 'open';
  approvedContacts?: string[];
}

export interface AppPreferences {
  id: string;
  theme: 'system' | 'light' | 'dark';
  activeAccountId?: string;
}

export type Page = 'home' | 'family' | 'add' | 'member-detail' | 'settings' | 'child-settings';
```

**Step 2: Write database layer**

```typescript
// family-app/src/lib/db.ts
// IndexedDB storage for My Signet family app

import { openDB, type IDBPDatabase } from 'idb';
import type { FamilyIdentity, FamilyMember, ChildSettings, AppPreferences } from '../types';

const DB_NAME = 'my-signet';
const DB_VERSION = 1;

let dbPromise: Promise<IDBPDatabase> | null = null;

function getDB(): Promise<IDBPDatabase> {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains('identity')) {
          db.createObjectStore('identity', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('family')) {
          const family = db.createObjectStore('family', { keyPath: 'pubkey' });
          family.createIndex('ownerPubkey', 'ownerPubkey');
        }
        if (!db.objectStoreNames.contains('child-settings')) {
          db.createObjectStore('child-settings', { keyPath: 'childPubkey' });
        }
        if (!db.objectStoreNames.contains('preferences')) {
          db.createObjectStore('preferences', { keyPath: 'id' });
        }
      },
    });
  }
  return dbPromise;
}

// --- Identity ---

export async function getIdentity(pubkey: string): Promise<FamilyIdentity | undefined> {
  const db = await getDB();
  return db.get('identity', pubkey);
}

export async function getAllIdentities(): Promise<FamilyIdentity[]> {
  const db = await getDB();
  return db.getAll('identity');
}

export async function saveIdentity(identity: FamilyIdentity): Promise<void> {
  const db = await getDB();
  await db.put('identity', identity);
}

export async function deleteIdentityRecord(pubkey: string): Promise<void> {
  const db = await getDB();
  await db.delete('identity', pubkey);
}

// --- Family Members ---

export async function getFamilyMembers(ownerPubkey: string): Promise<FamilyMember[]> {
  const db = await getDB();
  return db.getAllFromIndex('family', 'ownerPubkey', ownerPubkey);
}

export async function getFamilyMember(pubkey: string): Promise<FamilyMember | undefined> {
  const db = await getDB();
  return db.get('family', pubkey);
}

export async function saveFamilyMember(member: FamilyMember): Promise<void> {
  const db = await getDB();
  await db.put('family', member);
}

export async function deleteFamilyMember(pubkey: string): Promise<void> {
  const db = await getDB();
  await db.delete('family', pubkey);
}

// --- Child Settings ---

export async function getChildSettings(childPubkey: string): Promise<ChildSettings | undefined> {
  const db = await getDB();
  return db.get('child-settings', childPubkey);
}

export async function saveChildSettings(settings: ChildSettings): Promise<void> {
  const db = await getDB();
  await db.put('child-settings', settings);
}

// --- Preferences ---

export async function getPreferences(): Promise<AppPreferences> {
  const db = await getDB();
  const prefs = await db.get('preferences', 'current');
  return prefs || { id: 'current', theme: 'system' };
}

export async function savePreferences(prefs: AppPreferences): Promise<void> {
  const db = await getDB();
  await db.put('preferences', prefs);
}
```

**Step 3: Verify typecheck passes**

```bash
cd family-app && npm run typecheck
```

**Step 4: Commit**

```bash
git add family-app/src/types.ts family-app/src/lib/db.ts
git commit -m "feat(family-app): add types and IndexedDB storage layer"
```

---

## Task 4: Protocol Library Wrapper

**Files:**
- Create: `family-app/src/lib/signet.ts`

**Step 1: Write the protocol wrapper**

This is a simplified version of `app/src/lib/signet.ts` — only the functions the family app needs.

```typescript
// family-app/src/lib/signet.ts
// Simplified protocol library wrapper for My Signet

import {
  generateMnemonic,
  validateMnemonic,
  deriveNostrKeyPair,
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  getSignetDisplay,
  verifySignetWords,
  encodeNpub,
  createVouch,
  computeBadge,
  buildBadgeFilters,
} from 'signet-protocol';
import type { FamilyIdentity } from '../types';

export {
  computeSharedSecret,
  createQRPayload,
  serializeQRPayload,
  parseQRPayload,
  getSignetDisplay,
  verifySignetWords,
  encodeNpub,
  createVouch,
  computeBadge,
  buildBadgeFilters,
  validateMnemonic,
};

/** Create a new identity from a fresh mnemonic */
export function createNewIdentity(displayName: string, isChild: boolean, guardianPubkey?: string): FamilyIdentity {
  const mnemonic = generateMnemonic();
  const { privateKey, publicKey } = deriveNostrKeyPair(mnemonic);

  return {
    id: publicKey,
    publicKey,
    privateKey,
    mnemonic,
    displayName,
    isChild,
    guardianPubkey,
    createdAt: Math.floor(Date.now() / 1000),
  };
}

/** Restore an identity from an existing mnemonic */
export function importFromMnemonic(mnemonic: string, displayName: string, isChild: boolean, guardianPubkey?: string): FamilyIdentity {
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid recovery phrase');
  }
  const { privateKey, publicKey } = deriveNostrKeyPair(mnemonic);

  return {
    id: publicKey,
    publicKey,
    privateKey,
    mnemonic,
    displayName,
    isChild,
    guardianPubkey,
    createdAt: Math.floor(Date.now() / 1000),
  };
}
```

**Step 2: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 3: Commit**

```bash
git add family-app/src/lib/signet.ts
git commit -m "feat(family-app): add simplified protocol library wrapper"
```

---

## Task 5: Hooks

**Files:**
- Create: `family-app/src/hooks/useIdentity.ts`
- Create: `family-app/src/hooks/useFamily.ts`
- Create: `family-app/src/hooks/useSignetWords.ts`
- Create: `family-app/src/hooks/useCamera.ts`
- Create: `family-app/src/hooks/usePreferences.ts`

**Step 1: Write useIdentity hook**

```typescript
// family-app/src/hooks/useIdentity.ts
import { useState, useEffect, useCallback } from 'react';
import type { FamilyIdentity } from '../types';
import * as db from '../lib/db';
import { createNewIdentity, importFromMnemonic } from '../lib/signet';

export function useIdentity() {
  const [identities, setIdentities] = useState<FamilyIdentity[]>([]);
  const [activeIdentity, setActiveIdentity] = useState<FamilyIdentity | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAll = useCallback(async () => {
    const all = await db.getAllIdentities();
    setIdentities(all);
    const prefs = await db.getPreferences();
    const active = prefs.activeAccountId
      ? all.find(i => i.id === prefs.activeAccountId) || all[0]
      : all[0];
    setActiveIdentity(active || null);
    setLoading(false);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const create = useCallback(async (displayName: string, isChild: boolean, guardianPubkey?: string) => {
    const identity = createNewIdentity(displayName, isChild, guardianPubkey);
    await db.saveIdentity(identity);
    await db.savePreferences({ ...(await db.getPreferences()), activeAccountId: identity.id });
    await loadAll();
    return identity;
  }, [loadAll]);

  const restore = useCallback(async (mnemonic: string, displayName: string, isChild: boolean, guardianPubkey?: string) => {
    const identity = importFromMnemonic(mnemonic, displayName, isChild, guardianPubkey);
    await db.saveIdentity(identity);
    await db.savePreferences({ ...(await db.getPreferences()), activeAccountId: identity.id });
    await loadAll();
    return identity;
  }, [loadAll]);

  const remove = useCallback(async (pubkey?: string) => {
    const target = pubkey || activeIdentity?.id;
    if (!target) return;
    await db.deleteIdentityRecord(target);
    const prefs = await db.getPreferences();
    if (prefs.activeAccountId === target) {
      await db.savePreferences({ ...prefs, activeAccountId: undefined });
    }
    await loadAll();
  }, [activeIdentity, loadAll]);

  return { identity: activeIdentity, identities, loading, create, restore, remove };
}
```

**Step 2: Write useFamily hook**

```typescript
// family-app/src/hooks/useFamily.ts
import { useState, useEffect, useCallback } from 'react';
import type { FamilyMember } from '../types';
import * as db from '../lib/db';

export function useFamily(ownerPubkey: string | undefined) {
  const [members, setMembers] = useState<FamilyMember[]>([]);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    if (!ownerPubkey) { setMembers([]); setLoading(false); return; }
    const all = await db.getFamilyMembers(ownerPubkey);
    setMembers(all.sort((a, b) => b.verifiedAt - a.verifiedAt));
    setLoading(false);
  }, [ownerPubkey]);

  useEffect(() => { reload(); }, [reload]);

  const addMember = useCallback(async (member: FamilyMember) => {
    await db.saveFamilyMember(member);
    await reload();
  }, [reload]);

  const removeMember = useCallback(async (pubkey: string) => {
    await db.deleteFamilyMember(pubkey);
    await reload();
  }, [reload]);

  return { members, loading, addMember, removeMember, reload };
}
```

**Step 3: Write useSignetWords hook** (port from dev app)

```typescript
// family-app/src/hooks/useSignetWords.ts
import { useState, useEffect } from 'react';
import { getSignetDisplay } from '../lib/signet';

export function useSignetWords(sharedSecret: string | null) {
  const [display, setDisplay] = useState<{ words: string[]; formatted: string; expiresIn: number }>({
    words: [], formatted: '', expiresIn: 0,
  });

  useEffect(() => {
    if (!sharedSecret) return;
    const update = () => {
      const result = getSignetDisplay(sharedSecret);
      setDisplay(result);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [sharedSecret]);

  return display;
}
```

**Step 4: Write useCamera hook** (port from dev app)

```typescript
// family-app/src/hooks/useCamera.ts
import { useState, useCallback } from 'react';

export function useCamera() {
  const [hasPermission, setHasPermission] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const requestPermission = useCallback(async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      });
      stream.getTracks().forEach(t => t.stop());
      setHasPermission(true);
      setError(null);
    } catch (err: any) {
      setHasPermission(false);
      if (err.name === 'NotAllowedError') {
        setError('Camera permission denied. Please allow camera access in your browser settings.');
      } else if (err.name === 'NotFoundError') {
        setError('No camera found on this device.');
      } else {
        setError('Could not access camera.');
      }
    }
  }, []);

  return { hasPermission, error, requestPermission };
}
```

**Step 5: Write usePreferences hook** (port from dev app, simplified)

```typescript
// family-app/src/hooks/usePreferences.ts
import { useState, useEffect, useCallback } from 'react';
import type { AppPreferences } from '../types';
import * as db from '../lib/db';

export function usePreferences() {
  const [preferences, setPreferences] = useState<AppPreferences>({ id: 'current', theme: 'system' });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    db.getPreferences().then(p => { setPreferences(p); setLoading(false); });
  }, []);

  useEffect(() => {
    if (preferences.theme === 'system') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', preferences.theme);
    }
  }, [preferences.theme]);

  const setTheme = useCallback(async (theme: 'system' | 'light' | 'dark') => {
    const updated = { ...preferences, theme };
    setPreferences(updated);
    await db.savePreferences(updated);
  }, [preferences]);

  return { preferences, loading, setTheme };
}
```

**Step 6: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 7: Commit**

```bash
git add family-app/src/hooks/
git commit -m "feat(family-app): add hooks (identity, family, signet words, camera, preferences)"
```

---

## Task 6: Shared Components

**Files:**
- Create: `family-app/src/components/BottomNav.tsx`
- Create: `family-app/src/components/Layout.tsx`
- Create: `family-app/src/components/QRCode.tsx`
- Create: `family-app/src/components/QRScanner.tsx`
- Create: `family-app/src/components/TrustBar.tsx`
- Create: `family-app/src/components/StatusBadge.tsx`
- Create: `family-app/src/components/SignetWords.tsx`
- Create: `family-app/src/components/WordInput.tsx`

**Step 1: Write BottomNav**

```typescript
// family-app/src/components/BottomNav.tsx
import type { Page } from '../types';

interface Props {
  activePage: Page;
  onNavigate: (page: Page) => void;
}

export function BottomNav({ activePage, onNavigate }: Props) {
  const isActive = (page: Page) => activePage === page;

  return (
    <nav style={{
      position: 'fixed',
      bottom: 0,
      left: 0,
      right: 0,
      height: 'var(--nav-height)',
      background: 'var(--bg-card)',
      borderTop: '1px solid var(--border)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-around',
      zIndex: 100,
      paddingBottom: 'env(safe-area-inset-bottom)',
    }}>
      <NavTab label="My Signet" active={isActive('home')} onClick={() => onNavigate('home')} />
      <AddButton active={isActive('add')} onClick={() => onNavigate('add')} />
      <NavTab label="My Family" active={isActive('family')} onClick={() => onNavigate('family')} />
    </nav>
  );
}

function NavTab({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: 'none',
        border: 'none',
        color: active ? 'var(--accent)' : 'var(--text-secondary)',
        fontSize: '0.75rem',
        fontWeight: active ? 700 : 500,
        cursor: 'pointer',
        padding: '8px 16px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: '2px',
        transition: 'color 200ms ease',
      }}
    >
      {active && <span style={{
        width: 4, height: 4, borderRadius: '50%',
        background: 'var(--accent)', marginBottom: 2,
      }} />}
      <span>{label}</span>
    </button>
  );
}

function AddButton({ active, onClick }: { active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: 56,
        height: 56,
        borderRadius: '50%',
        background: active ? 'var(--accent-hover)' : 'var(--accent)',
        color: '#FFFFFF',
        border: 'none',
        fontSize: '1.5rem',
        fontWeight: 300,
        cursor: 'pointer',
        marginTop: -20,
        boxShadow: 'var(--shadow-lg)',
        transition: 'background 200ms ease, transform 100ms ease',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      +
    </button>
  );
}
```

**Step 2: Write Layout**

```typescript
// family-app/src/components/Layout.tsx
import type { ReactNode } from 'react';
import type { Page } from '../types';
import { BottomNav } from './BottomNav';

interface Props {
  activePage: Page;
  onNavigate: (page: Page) => void;
  onSettingsOpen: () => void;
  title?: string;
  showBack?: boolean;
  onBack?: () => void;
  children: ReactNode;
}

export function Layout({ activePage, onNavigate, onSettingsOpen, title, showBack, onBack, children }: Props) {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <header style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 16px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-card)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {showBack && (
            <button onClick={onBack} style={{
              background: 'none', border: 'none', color: 'var(--accent)',
              fontSize: '1rem', cursor: 'pointer', padding: '4px 8px',
            }}>
              &larr;
            </button>
          )}
          <h2 style={{ margin: 0 }}>{title || 'My Signet'}</h2>
        </div>
        {!showBack && (
          <button onClick={onSettingsOpen} style={{
            background: 'none', border: 'none', color: 'var(--text-secondary)',
            fontSize: '1.25rem', cursor: 'pointer', padding: '4px 8px',
          }}>
            &#9881;
          </button>
        )}
      </header>
      <main className="page" style={{ flex: 1 }}>
        {children}
      </main>
      {!showBack && <BottomNav activePage={activePage} onNavigate={onNavigate} />}
    </div>
  );
}
```

**Step 3: Write QRCode** (port from dev app)

```typescript
// family-app/src/components/QRCode.tsx
import { useEffect, useRef } from 'react';
import QRCodeLib from 'qrcode';

interface Props {
  data: string;
  size?: number;
}

export function QRCode({ data, size = 200 }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!canvasRef.current) return;
    QRCodeLib.toCanvas(canvasRef.current, data, {
      width: size,
      margin: 1,
      color: { dark: '#1A1A2E', light: '#FFFFFF' },
    });
  }, [data, size]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        borderRadius: 'var(--radius)',
        background: '#FFFFFF',
        padding: 8,
        border: '1px solid var(--border)',
      }}
    />
  );
}
```

**Step 4: Write QRScanner** (port from dev app, simplified)

```typescript
// family-app/src/components/QRScanner.tsx
import { useEffect, useRef, useCallback } from 'react';
import { Html5Qrcode } from 'html5-qrcode';

interface Props {
  onScan: (data: string) => void;
  active: boolean;
}

export function QRScanner({ onScan, active }: Props) {
  const scannerRef = useRef<Html5Qrcode | null>(null);
  const onScanRef = useRef(onScan);
  onScanRef.current = onScan;

  const stopScanner = useCallback(async () => {
    if (scannerRef.current) {
      try {
        const state = scannerRef.current.getState();
        if (state === 2) await scannerRef.current.stop();
        scannerRef.current.clear();
      } catch { /* ignore cleanup errors */ }
      scannerRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!active) { stopScanner(); return; }

    const scanner = new Html5Qrcode('signet-qr-scanner');
    scannerRef.current = scanner;

    scanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 250, height: 250 } },
      (text) => { onScanRef.current(text); },
      () => {},
    ).catch(() => {});

    return () => { stopScanner(); };
  }, [active, stopScanner]);

  return <div id="signet-qr-scanner" style={{ width: '100%', borderRadius: 'var(--radius)', overflow: 'hidden' }} />;
}
```

**Step 5: Write TrustBar**

```typescript
// family-app/src/components/TrustBar.tsx
interface Props {
  score: number;
  label?: string;
}

export function TrustBar({ score, label }: Props) {
  const color = score >= 60 ? 'var(--success)' : score >= 30 ? 'var(--warning)' : 'var(--danger)';

  return (
    <div>
      {label && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{label}</span>
          <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>{score}%</span>
        </div>
      )}
      <div className="trust-bar">
        <div className="trust-bar-fill" style={{ width: `${Math.min(score, 100)}%`, background: color }} />
      </div>
    </div>
  );
}
```

**Step 6: Write StatusBadge**

```typescript
// family-app/src/components/StatusBadge.tsx
interface Props {
  isVerified: boolean;
  isChild?: boolean;
}

export function StatusBadge({ isVerified, isChild }: Props) {
  if (isChild) {
    return <span className="badge badge-child">Child Account</span>;
  }
  if (isVerified) {
    return <span className="badge badge-verified">Verified</span>;
  }
  return <span className="badge badge-unverified">Unverified</span>;
}
```

**Step 7: Write SignetWords** (anti-deepfake display + verify)

```typescript
// family-app/src/components/SignetWords.tsx
import { useState } from 'react';
import { useSignetWords } from '../hooks/useSignetWords';
import { verifySignetWords } from '../lib/signet';
import { WordInput } from './WordInput';

interface Props {
  sharedSecret: string;
}

export function SignetWords({ sharedSecret }: Props) {
  const { words, expiresIn } = useSignetWords(sharedSecret);
  const [mode, setMode] = useState<'display' | 'verify'>('display');
  const [result, setResult] = useState<'match' | 'no-match' | null>(null);

  const handleVerify = (inputWords: string[]) => {
    const matched = verifySignetWords(sharedSecret, inputWords);
    setResult(matched ? 'match' : 'no-match');
    if (matched) {
      setTimeout(() => { setResult(null); setMode('display'); }, 2000);
    }
  };

  if (mode === 'verify') {
    return (
      <div className="card section">
        <h3 style={{ marginBottom: 8 }}>Verify their words</h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 16 }}>
          Enter the 3 words they read to you:
        </p>
        {result === 'no-match' && (
          <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>
            Words don't match. This might not be who they claim to be.
          </div>
        )}
        <WordInput onSubmit={handleVerify} />
        <button className="btn btn-ghost" onClick={() => { setMode('display'); setResult(null); }} style={{ marginTop: 8 }}>
          Cancel
        </button>
      </div>
    );
  }

  return (
    <div className="card section">
      <h3 style={{ marginBottom: 4 }}>Signet Me</h3>
      <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 16 }}>
        Ask them to read these words aloud:
      </p>
      {result === 'match' && (
        <div className="checkmark-anim" style={{ padding: 8, background: 'var(--success-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--success)', textAlign: 'center', fontWeight: 600 }}>
          Confirmed — it's really them.
        </div>
      )}
      <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginBottom: 12 }}>
        {words.map((word, i) => (
          <span key={i} className="signet-word">{word}</span>
        ))}
      </div>
      <div style={{ textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 16 }}>
        Words refresh in {expiresIn}s
      </div>
      <button className="btn btn-secondary" onClick={() => setMode('verify')}>
        Verify words read to me
      </button>
    </div>
  );
}
```

**Step 8: Write WordInput**

```typescript
// family-app/src/components/WordInput.tsx
import { useState } from 'react';

interface Props {
  onSubmit: (words: string[]) => void;
}

export function WordInput({ onSubmit }: Props) {
  const [w1, setW1] = useState('');
  const [w2, setW2] = useState('');
  const [w3, setW3] = useState('');

  const handleSubmit = () => {
    if (w1.trim() && w2.trim() && w3.trim()) {
      onSubmit([w1.trim().toLowerCase(), w2.trim().toLowerCase(), w3.trim().toLowerCase()]);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <input className="input" placeholder="Word 1" value={w1} onChange={e => setW1(e.target.value)} autoFocus />
        <input className="input" placeholder="Word 2" value={w2} onChange={e => setW2(e.target.value)} />
        <input className="input" placeholder="Word 3" value={w3} onChange={e => setW3(e.target.value)} />
      </div>
      <button className="btn btn-primary" onClick={handleSubmit} disabled={!w1.trim() || !w2.trim() || !w3.trim()}>
        Check
      </button>
    </div>
  );
}
```

**Step 9: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 10: Commit**

```bash
git add family-app/src/components/
git commit -m "feat(family-app): add shared components (nav, QR, Signet Words, trust bar, badges)"
```

---

## Task 7: Onboarding Page

**Files:**
- Create: `family-app/src/pages/Onboarding.tsx`

**Step 1: Write the onboarding page**

Three steps, no jargon. Create or import. Name. Recovery phrase. Optional child setup.

```typescript
// family-app/src/pages/Onboarding.tsx
import { useState } from 'react';
import { validateMnemonic } from '../lib/signet';

interface Props {
  onCreate: (displayName: string, isChild: boolean, guardianPubkey?: string) => Promise<{ mnemonic: string }>;
  onImport: (mnemonic: string, displayName: string, isChild: boolean, guardianPubkey?: string) => Promise<void>;
}

type Flow = 'welcome' | 'create' | 'import';
type CreateStep = 'name' | 'child-check' | 'guardian' | 'recovery' | 'done';
type ImportStep = 'phrase' | 'name' | 'done';

export function Onboarding({ onCreate, onImport }: Props) {
  const [flow, setFlow] = useState<Flow>('welcome');
  const [createStep, setCreateStep] = useState<CreateStep>('name');
  const [importStep, setImportStep] = useState<ImportStep>('phrase');

  // Shared state
  const [displayName, setDisplayName] = useState('');
  const [isChild, setIsChild] = useState(false);
  const [guardianPubkey, setGuardianPubkey] = useState('');
  const [mnemonic, setMnemonic] = useState('');
  const [importWords, setImportWords] = useState('');
  const [error, setError] = useState('');
  const [writtenDown, setWrittenDown] = useState(false);

  // --- Create flow ---
  const handleCreateName = () => {
    if (!displayName.trim()) return;
    setCreateStep('child-check');
  };

  const handleChildCheck = (child: boolean) => {
    setIsChild(child);
    if (child) {
      setCreateStep('guardian');
    } else {
      handleCreate(child);
    }
  };

  const handleGuardianSubmit = () => {
    if (guardianPubkey.length !== 64) {
      setError('Please enter a valid 64-character Signet ID');
      return;
    }
    setError('');
    handleCreate(true, guardianPubkey);
  };

  const handleCreate = async (child: boolean, guardian?: string) => {
    const result = await onCreate(displayName.trim(), child, guardian);
    setMnemonic(result.mnemonic);
    setCreateStep('recovery');
  };

  const handleRecoveryDone = () => {
    setCreateStep('done');
  };

  // --- Import flow ---
  const handleImportPhrase = () => {
    const words = importWords.trim().toLowerCase();
    if (!validateMnemonic(words)) {
      setError('Invalid recovery phrase. Please check your 12 words.');
      return;
    }
    setError('');
    setImportStep('name');
  };

  const handleImportComplete = async () => {
    if (!displayName.trim()) return;
    await onImport(importWords.trim().toLowerCase(), displayName.trim(), isChild, guardianPubkey || undefined);
  };

  // --- Render ---
  if (flow === 'welcome') {
    return (
      <div className="page fade-in" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', minHeight: '80vh' }}>
        <div style={{ textAlign: 'center', marginBottom: 48 }}>
          <h1 style={{ marginBottom: 8 }}>Welcome to Signet</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Your digital identity, owned by you.</p>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <button className="btn btn-primary" onClick={() => setFlow('create')}>Create My Signet</button>
          <button className="btn btn-secondary" onClick={() => setFlow('import')}>I have a recovery phrase</button>
        </div>
      </div>
    );
  }

  if (flow === 'create') {
    if (createStep === 'name') {
      return (
        <div className="page fade-in">
          <h1 style={{ marginBottom: 8 }}>What should people call you?</h1>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>This is your display name. You can change it later.</p>
          <input
            className="input"
            placeholder="Your name"
            value={displayName}
            onChange={e => setDisplayName(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleCreateName()}
            autoFocus
          />
          <button className="btn btn-primary" onClick={handleCreateName} disabled={!displayName.trim()} style={{ marginTop: 16 }}>
            Continue
          </button>
        </div>
      );
    }

    if (createStep === 'child-check') {
      return (
        <div className="page fade-in">
          <h1 style={{ marginBottom: 8 }}>Is this account for a child?</h1>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
            Child accounts are linked to a parent for safety.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <button className="btn btn-primary" onClick={() => handleChildCheck(false)}>No, this is for me</button>
            <button className="btn btn-secondary" onClick={() => handleChildCheck(true)}>Yes, this is for a child</button>
          </div>
        </div>
      );
    }

    if (createStep === 'guardian') {
      return (
        <div className="page fade-in">
          <h1 style={{ marginBottom: 8 }}>Link to parent</h1>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
            Enter the parent's Signet ID. They can find it on their My Signet home screen.
          </p>
          {error && <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>{error}</div>}
          <input
            className="input"
            placeholder="Parent's Signet ID (64 characters)"
            value={guardianPubkey}
            onChange={e => setGuardianPubkey(e.target.value.trim())}
            autoFocus
          />
          <button className="btn btn-primary" onClick={handleGuardianSubmit} style={{ marginTop: 16 }}>
            Continue
          </button>
          <button className="btn btn-ghost" onClick={() => setCreateStep('child-check')} style={{ marginTop: 8 }}>
            Back
          </button>
        </div>
      );
    }

    if (createStep === 'recovery') {
      return (
        <div className="page fade-in">
          <h1 style={{ marginBottom: 8 }}>Your recovery phrase</h1>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
            Write these 12 words down and keep them safe. If you lose your phone, these words are the only way to get your Signet back. Never share them with anyone.
          </p>
          <div className="card" style={{ marginBottom: 24 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {mnemonic.split(' ').map((word, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '6px 0' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', width: 20, textAlign: 'right' }}>{i + 1}</span>
                  <span style={{ fontWeight: 600 }}>{word}</span>
                </div>
              ))}
            </div>
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, cursor: 'pointer' }}>
            <input type="checkbox" checked={writtenDown} onChange={e => setWrittenDown(e.target.checked)} />
            <span style={{ fontSize: '0.9rem' }}>I've written these down</span>
          </label>
          <button className="btn btn-primary" onClick={handleRecoveryDone} disabled={!writtenDown}>
            Continue
          </button>
          <button
            className="btn btn-ghost"
            onClick={() => navigator.clipboard?.writeText(mnemonic)}
            style={{ marginTop: 8 }}
          >
            Copy to clipboard
          </button>
        </div>
      );
    }

    // done — App.tsx will detect identity exists and show home
    return null;
  }

  if (flow === 'import') {
    if (importStep === 'phrase') {
      return (
        <div className="page fade-in">
          <h1 style={{ marginBottom: 8 }}>Enter your recovery phrase</h1>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>Type or paste your 12 words, separated by spaces.</p>
          {error && <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>{error}</div>}
          <textarea
            className="input"
            rows={4}
            placeholder="word1 word2 word3 ..."
            value={importWords}
            onChange={e => setImportWords(e.target.value)}
            style={{ resize: 'none' }}
            autoFocus
          />
          <button className="btn btn-primary" onClick={handleImportPhrase} style={{ marginTop: 16 }}>
            Continue
          </button>
          <button className="btn btn-ghost" onClick={() => setFlow('welcome')} style={{ marginTop: 8 }}>
            Back
          </button>
        </div>
      );
    }

    if (importStep === 'name') {
      return (
        <div className="page fade-in">
          <h1 style={{ marginBottom: 8 }}>What should people call you?</h1>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>This is your display name.</p>
          <input
            className="input"
            placeholder="Your name"
            value={displayName}
            onChange={e => setDisplayName(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleImportComplete()}
            autoFocus
          />
          <button className="btn btn-primary" onClick={handleImportComplete} disabled={!displayName.trim()} style={{ marginTop: 16 }}>
            Restore My Signet
          </button>
        </div>
      );
    }

    return null;
  }

  return null;
}
```

**Step 2: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 3: Commit**

```bash
git add family-app/src/pages/Onboarding.tsx
git commit -m "feat(family-app): add onboarding page (create/import, 3 steps, child linking)"
```

---

## Task 8: Home Page (My Signet)

**Files:**
- Create: `family-app/src/pages/Home.tsx`

**Step 1: Write the home page**

```typescript
// family-app/src/pages/Home.tsx
import type { FamilyIdentity, FamilyMember } from '../types';
import { QRCode } from '../components/QRCode';
import { TrustBar } from '../components/TrustBar';
import { StatusBadge } from '../components/StatusBadge';
import { encodeNpub, serializeQRPayload, createQRPayload } from '../lib/signet';
import { useState } from 'react';

interface Props {
  identity: FamilyIdentity;
  familyCount: number;
}

export function Home({ identity, familyCount }: Props) {
  const [copied, setCopied] = useState(false);
  const npub = encodeNpub(identity.publicKey);
  const shortNpub = npub.slice(0, 12) + '...' + npub.slice(-8);

  const qrPayload = serializeQRPayload(
    createQRPayload(identity.publicKey, { name: identity.displayName })
  );

  const copyPubkey = () => {
    navigator.clipboard?.writeText(identity.publicKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Simple trust score: family members verified = basic trust
  const trustScore = Math.min(familyCount * 10 + 10, 100);

  return (
    <div className="fade-in">
      {/* Identity Card */}
      <div className="card section" style={{ textAlign: 'center' }}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
          <QRCode data={qrPayload} size={180} />
        </div>
        <h1 style={{ marginBottom: 4 }}>{identity.displayName}</h1>
        <StatusBadge isVerified={familyCount > 0} isChild={identity.isChild} />
      </div>

      {/* Trust Summary */}
      {!identity.isChild && (
        <div className="card section">
          <TrustBar score={trustScore} label="Trust" />
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 12, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            <span>Family: {familyCount} member{familyCount !== 1 ? 's' : ''} verified</span>
            <span>Since {new Date(identity.createdAt * 1000).toLocaleDateString('en-GB', { month: 'short', year: 'numeric' })}</span>
          </div>
        </div>
      )}

      {/* Child info */}
      {identity.isChild && identity.guardianPubkey && (
        <div className="card section">
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Linked to parent:
          </div>
          <div style={{ fontSize: '0.85rem', fontFamily: 'monospace', marginTop: 4, wordBreak: 'break-all' }}>
            {identity.guardianPubkey.slice(0, 16)}...{identity.guardianPubkey.slice(-8)}
          </div>
        </div>
      )}

      {/* Signet ID */}
      <div className="card section">
        <div className="section-title">Your Signet ID</div>
        <div style={{ fontFamily: 'monospace', fontSize: '0.85rem', wordBreak: 'break-all', marginBottom: 8 }}>
          {shortNpub}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-secondary" onClick={copyPubkey} style={{ flex: 1 }}>
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button className="btn btn-secondary" onClick={() => {
            navigator.share?.({ title: 'My Signet', text: identity.publicKey });
          }} style={{ flex: 1 }}>
            Share
          </button>
        </div>
      </div>
    </div>
  );
}
```

**Step 2: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 3: Commit**

```bash
git add family-app/src/pages/Home.tsx
git commit -m "feat(family-app): add home page (identity card, QR code, trust summary)"
```

---

## Task 9: Family List + Member Detail Pages

**Files:**
- Create: `family-app/src/pages/Family.tsx`
- Create: `family-app/src/pages/FamilyMember.tsx`

**Step 1: Write Family list page**

```typescript
// family-app/src/pages/Family.tsx
import type { FamilyMember as FamilyMemberType } from '../types';
import { StatusBadge } from '../components/StatusBadge';

interface Props {
  members: FamilyMemberType[];
  onSelectMember: (pubkey: string) => void;
}

export function Family({ members, onSelectMember }: Props) {
  if (members.length === 0) {
    return (
      <div className="fade-in" style={{ textAlign: 'center', paddingTop: 64 }}>
        <h2 style={{ marginBottom: 8 }}>No family members yet</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
          Tap the + button to add someone and verify it's really them.
        </p>
      </div>
    );
  }

  return (
    <div className="fade-in">
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
        "Signet Me" is how you know it's really them, not a deepfake.
      </p>
    </div>
  );
}
```

**Step 2: Write FamilyMember detail page**

```typescript
// family-app/src/pages/FamilyMember.tsx
import type { FamilyMember as FamilyMemberType } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { SignetWords } from '../components/SignetWords';
import { useState } from 'react';

interface Props {
  member: FamilyMemberType;
  onRemove: (pubkey: string) => void;
}

export function FamilyMemberDetail({ member, onRemove }: Props) {
  const [confirmRemove, setConfirmRemove] = useState(false);

  return (
    <div className="fade-in">
      {/* Member info */}
      <div className="card section" style={{ textAlign: 'center' }}>
        <h1 style={{ marginBottom: 4 }}>{member.displayName}</h1>
        <StatusBadge isVerified={true} isChild={member.isChild} />
        <div style={{ marginTop: 8, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Connected {new Date(member.verifiedAt * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}
        </div>
      </div>

      {/* Signet Me — the core feature */}
      <SignetWords sharedSecret={member.sharedSecret} />

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
```

**Step 3: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 4: Commit**

```bash
git add family-app/src/pages/Family.tsx family-app/src/pages/FamilyMember.tsx
git commit -m "feat(family-app): add family list and member detail pages with Signet Me"
```

---

## Task 10: Add Member Page (QR Scan + ID Entry)

**Files:**
- Create: `family-app/src/pages/AddMember.tsx`

**Step 1: Write the Add Member page**

```typescript
// family-app/src/pages/AddMember.tsx
import { useState } from 'react';
import { useCamera } from '../hooks/useCamera';
import { QRScanner } from '../components/QRScanner';
import { QRCode } from '../components/QRCode';
import { SignetWords } from '../components/SignetWords';
import { parseQRPayload, computeSharedSecret, serializeQRPayload, createQRPayload } from '../lib/signet';
import type { FamilyIdentity, FamilyMember } from '../types';

interface Props {
  identity: FamilyIdentity;
  onAddMember: (member: FamilyMember) => Promise<void>;
  onDone: () => void;
}

type Step = 'choose' | 'scan' | 'show-qr' | 'enter-id' | 'preview' | 'success';

export function AddMember({ identity, onAddMember, onDone }: Props) {
  const { hasPermission, error: cameraError, requestPermission } = useCamera();
  const [step, setStep] = useState<Step>('choose');
  const [theirPubkey, setTheirPubkey] = useState('');
  const [theirName, setTheirName] = useState('');
  const [sharedSecret, setSharedSecret] = useState('');
  const [idInput, setIdInput] = useState('');
  const [error, setError] = useState('');

  const qrPayload = serializeQRPayload(
    createQRPayload(identity.publicKey, { name: identity.displayName })
  );

  const handleScan = (data: string) => {
    try {
      const payload = parseQRPayload(data);
      if (!payload?.pubkey) throw new Error('Invalid QR code');
      setTheirPubkey(payload.pubkey);
      setTheirName(payload.info?.name || 'Unknown');
      setStep('preview');
    } catch {
      setError('Could not read QR code. Please try again.');
    }
  };

  const handleIdSubmit = () => {
    const cleaned = idInput.trim();
    if (cleaned.length !== 64 || !/^[0-9a-f]+$/i.test(cleaned)) {
      setError('Please enter a valid 64-character Signet ID');
      return;
    }
    setTheirPubkey(cleaned);
    setTheirName('');
    setStep('preview');
  };

  const handleConfirm = async () => {
    const secret = computeSharedSecret(identity.privateKey, theirPubkey);
    setSharedSecret(secret);
    await onAddMember({
      pubkey: theirPubkey,
      ownerPubkey: identity.publicKey,
      displayName: theirName || 'Family member',
      sharedSecret: secret,
      verifiedAt: Math.floor(Date.now() / 1000),
    });
    setStep('success');
  };

  if (step === 'choose') {
    return (
      <div className="fade-in">
        <div className="section">
          <h2 style={{ marginBottom: 4 }}>In person?</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 12 }}>
            Scan their QR code, or show yours for them to scan.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button className="btn btn-primary" onClick={() => {
              if (hasPermission === null) requestPermission().then(() => setStep('scan'));
              else setStep('scan');
            }}>
              Scan their QR code
            </button>
            <button className="btn btn-secondary" onClick={() => setStep('show-qr')}>
              Show my QR code
            </button>
          </div>
        </div>

        <div className="section">
          <h2 style={{ marginBottom: 4 }}>Remote?</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 12 }}>
            For phone or video calls — enter their Signet ID.
          </p>
          <button className="btn btn-secondary" onClick={() => setStep('enter-id')}>
            Enter their Signet ID
          </button>
        </div>
      </div>
    );
  }

  if (step === 'scan') {
    return (
      <div className="fade-in">
        <h2 style={{ marginBottom: 16 }}>Scan their QR code</h2>
        {cameraError && (
          <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>
            {cameraError}
          </div>
        )}
        {error && (
          <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>
            {error}
          </div>
        )}
        <QRScanner onScan={handleScan} active={hasPermission === true} />
        {hasPermission === null && (
          <button className="btn btn-primary" onClick={requestPermission} style={{ marginTop: 16 }}>
            Allow camera access
          </button>
        )}
        <button className="btn btn-ghost" onClick={() => { setStep('choose'); setError(''); }} style={{ marginTop: 12 }}>
          Back
        </button>
      </div>
    );
  }

  if (step === 'show-qr') {
    return (
      <div className="fade-in" style={{ textAlign: 'center' }}>
        <h2 style={{ marginBottom: 8 }}>Show this to them</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 16 }}>
          Ask them to scan this QR code with their Signet app.
        </p>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
          <QRCode data={qrPayload} size={240} />
        </div>
        <button className="btn btn-ghost" onClick={() => setStep('choose')}>Back</button>
      </div>
    );
  }

  if (step === 'enter-id') {
    return (
      <div className="fade-in">
        <h2 style={{ marginBottom: 8 }}>Enter their Signet ID</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 16 }}>
          Ask them to copy their Signet ID and send it to you.
        </p>
        {error && (
          <div style={{ padding: 8, background: 'var(--danger-light)', borderRadius: 'var(--radius-sm)', marginBottom: 12, color: 'var(--danger)', fontSize: '0.9rem' }}>
            {error}
          </div>
        )}
        <input
          className="input"
          placeholder="64-character Signet ID"
          value={idInput}
          onChange={e => setIdInput(e.target.value.trim())}
          autoFocus
        />
        <button className="btn btn-primary" onClick={handleIdSubmit} disabled={!idInput.trim()} style={{ marginTop: 16 }}>
          Continue
        </button>
        <button className="btn btn-ghost" onClick={() => { setStep('choose'); setError(''); }} style={{ marginTop: 8 }}>
          Back
        </button>
      </div>
    );
  }

  if (step === 'preview') {
    return (
      <div className="fade-in" style={{ textAlign: 'center' }}>
        <h2 style={{ marginBottom: 16 }}>Add to family?</h2>
        <div className="card" style={{ marginBottom: 24 }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: 4 }}>
            {theirName || 'Unknown person'}
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
            {theirPubkey.slice(0, 16)}...{theirPubkey.slice(-8)}
          </div>
        </div>
        {!theirName && (
          <div style={{ marginBottom: 16 }}>
            <input
              className="input"
              placeholder="What should we call them?"
              value={theirName}
              onChange={e => setTheirName(e.target.value)}
            />
          </div>
        )}
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary" onClick={handleConfirm} style={{ flex: 1 }}>
            Add to family
          </button>
          <button className="btn btn-secondary" onClick={() => { setStep('choose'); setError(''); }} style={{ flex: 1 }}>
            Cancel
          </button>
        </div>
      </div>
    );
  }

  if (step === 'success') {
    return (
      <div className="fade-in" style={{ textAlign: 'center' }}>
        <div className="checkmark-anim" style={{ fontSize: '3rem', marginBottom: 8 }}>&#10003;</div>
        <h2 style={{ marginBottom: 8 }}>{theirName || 'Family member'} added</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: 24 }}>
          Use Signet Me below to verify it's really them.
        </p>
        {sharedSecret && <SignetWords sharedSecret={sharedSecret} />}
        <button className="btn btn-primary" onClick={onDone} style={{ marginTop: 16 }}>
          Done
        </button>
      </div>
    );
  }

  return null;
}
```

**Step 2: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 3: Commit**

```bash
git add family-app/src/pages/AddMember.tsx
git commit -m "feat(family-app): add member page (QR scan, show QR, enter ID, Signet Me)"
```

---

## Task 11: Settings + Child Settings Pages

**Files:**
- Create: `family-app/src/pages/Settings.tsx`
- Create: `family-app/src/pages/ChildSettings.tsx`

**Step 1: Write Settings page**

```typescript
// family-app/src/pages/Settings.tsx
import { useState } from 'react';
import type { FamilyIdentity, AppPreferences } from '../types';

interface Props {
  identity: FamilyIdentity;
  preferences: AppPreferences;
  onSetTheme: (theme: 'system' | 'light' | 'dark') => void;
  onDeleteIdentity: () => void;
  onOpenChildSettings: () => void;
  hasChildren: boolean;
}

export function Settings({ identity, preferences, onSetTheme, onDeleteIdentity, onOpenChildSettings, hasChildren }: Props) {
  const [showRecovery, setShowRecovery] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [copied, setCopied] = useState(false);

  return (
    <div className="fade-in">
      {/* Name */}
      <div className="card section">
        <div className="section-title">My Name</div>
        <div style={{ fontWeight: 600 }}>{identity.displayName}</div>
      </div>

      {/* Recovery Phrase */}
      <div className="card section">
        <div className="section-title">Recovery Phrase</div>
        {!showRecovery ? (
          <button className="btn btn-secondary" onClick={() => setShowRecovery(true)}>
            View my 12 words
          </button>
        ) : (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 12 }}>
              {identity.mnemonic.split(' ').map((word, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '4px 0' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem', width: 20, textAlign: 'right' }}>{i + 1}</span>
                  <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{word}</span>
                </div>
              ))}
            </div>
            <button className="btn btn-ghost" onClick={() => {
              navigator.clipboard?.writeText(identity.mnemonic);
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            }}>
              {copied ? 'Copied!' : 'Copy to clipboard'}
            </button>
            <button className="btn btn-ghost" onClick={() => setShowRecovery(false)}>
              Hide
            </button>
          </div>
        )}
      </div>

      {/* Appearance */}
      <div className="card section">
        <div className="section-title">Appearance</div>
        <div style={{ display: 'flex', gap: 8 }}>
          {(['system', 'light', 'dark'] as const).map(theme => (
            <button
              key={theme}
              className={`btn ${preferences.theme === theme ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => onSetTheme(theme)}
              style={{ flex: 1, padding: '8px 12px', fontSize: '0.85rem' }}
            >
              {theme.charAt(0).toUpperCase() + theme.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Child Accounts */}
      {hasChildren && (
        <div className="card section">
          <div className="section-title">Child Accounts</div>
          <button className="btn btn-secondary" onClick={onOpenChildSettings}>
            Manage linked children
          </button>
        </div>
      )}

      {/* Export */}
      <div className="card section">
        <div className="section-title">Export My Signet</div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
          Take your identity to another app.
        </p>
        <button className="btn btn-secondary" onClick={() => {
          const data = JSON.stringify({ mnemonic: identity.mnemonic, displayName: identity.displayName });
          const blob = new Blob([data], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'my-signet-backup.json';
          a.click();
          URL.revokeObjectURL(url);
        }}>
          Export backup
        </button>
      </div>

      {/* Delete */}
      <div className="section" style={{ marginTop: 32 }}>
        {!confirmDelete ? (
          <button className="btn btn-ghost" onClick={() => setConfirmDelete(true)} style={{ color: 'var(--danger)' }}>
            Delete My Signet
          </button>
        ) : (
          <div className="card" style={{ borderColor: 'var(--danger)' }}>
            <p style={{ marginBottom: 12, fontSize: '0.9rem' }}>
              This will permanently delete your identity from this device. Make sure you've saved your recovery phrase.
            </p>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-danger" onClick={onDeleteIdentity} style={{ flex: 1 }}>Delete forever</button>
              <button className="btn btn-secondary" onClick={() => setConfirmDelete(false)} style={{ flex: 1 }}>Cancel</button>
            </div>
          </div>
        )}
      </div>

      {/* About */}
      <div style={{ textAlign: 'center', marginTop: 32, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
        <div>My Signet v1.0.0</div>
        <div>Open source identity verification</div>
      </div>
    </div>
  );
}
```

**Step 2: Write ChildSettings page**

```typescript
// family-app/src/pages/ChildSettings.tsx
import { useState, useEffect, useCallback } from 'react';
import type { FamilyIdentity, ChildSettings as ChildSettingsType } from '../types';
import * as db from '../lib/db';

interface Props {
  identity: FamilyIdentity;
  childIdentities: FamilyIdentity[];
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
            <h3 style={{ marginBottom: 4 }}>{child.displayName}</h3>
            {child.ageRange && (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: 12 }}>
                Age range: {child.ageRange}
              </div>
            )}
            <div className="section-title">Who can contact {child.displayName}?</div>
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
```

**Step 3: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 4: Commit**

```bash
git add family-app/src/pages/Settings.tsx family-app/src/pages/ChildSettings.tsx
git commit -m "feat(family-app): add settings and persisted child settings pages"
```

---

## Task 12: Wire Up App.tsx (Router + State)

**Files:**
- Modify: `family-app/src/App.tsx`

**Step 1: Write the full App component**

Replace the placeholder `App.tsx` with the full router that connects all pages and hooks.

```typescript
// family-app/src/App.tsx
import { useState, useCallback } from 'react';
import type { Page, FamilyMember } from './types';
import { useIdentity } from './hooks/useIdentity';
import { useFamily } from './hooks/useFamily';
import { usePreferences } from './hooks/usePreferences';
import { Layout } from './components/Layout';
import { Onboarding } from './pages/Onboarding';
import { Home } from './pages/Home';
import { Family } from './pages/Family';
import { FamilyMemberDetail } from './pages/FamilyMember';
import { AddMember } from './pages/AddMember';
import { Settings } from './pages/Settings';
import { ChildSettingsPage } from './pages/ChildSettings';

export function App() {
  const { identity, identities, loading: identityLoading, create, restore, remove } = useIdentity();
  const { members, addMember, removeMember } = useFamily(identity?.id);
  const { preferences, loading: prefsLoading, setTheme } = usePreferences();

  const [page, setPage] = useState<Page>('home');
  const [selectedMemberPubkey, setSelectedMemberPubkey] = useState<string | null>(null);

  const handleCreate = useCallback(async (displayName: string, isChild: boolean, guardianPubkey?: string) => {
    const created = await create(displayName, isChild, guardianPubkey);
    return { mnemonic: created.mnemonic };
  }, [create]);

  const handleImport = useCallback(async (mnemonic: string, displayName: string, isChild: boolean, guardianPubkey?: string) => {
    await restore(mnemonic, displayName, isChild, guardianPubkey);
  }, [restore]);

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

  // Loading
  if (identityLoading || prefsLoading) {
    return <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', color: 'var(--text-secondary)' }}>Loading...</div>;
  }

  // No identity — show onboarding
  if (!identity) {
    return <Onboarding onCreate={handleCreate} onImport={handleImport} />;
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
          onSetTheme={setTheme}
          onDeleteIdentity={remove}
          onOpenChildSettings={() => setPage('child-settings')}
          hasChildren={childIdentities.length > 0}
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
        <FamilyMemberDetail member={member} onRemove={handleRemoveMember} />
      </Layout>
    );
  }

  // Add member
  if (page === 'add') {
    return (
      <Layout activePage={page} onNavigate={setPage} onSettingsOpen={() => setPage('settings')} title="Add Family Member" showBack onBack={() => setPage('home')}>
        <AddMember identity={identity} onAddMember={addMember} onDone={handleAddDone} />
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

  // Home (default)
  return (
    <Layout activePage="home" onNavigate={setPage} onSettingsOpen={() => setPage('settings')}>
      <Home identity={identity} familyCount={members.length} />
    </Layout>
  );
}
```

**Step 2: Verify typecheck**

```bash
cd family-app && npm run typecheck
```

**Step 3: Verify dev server starts and renders**

```bash
cd family-app && npm run dev
```

Open https://localhost:5175 — should show the onboarding welcome screen.

**Step 4: Commit**

```bash
git add family-app/src/App.tsx
git commit -m "feat(family-app): wire up App.tsx router connecting all pages and hooks"
```

---

## Task 13: Smoke Test + Final Polish

**Files:**
- Possibly modify: any file that fails typecheck or has minor issues

**Step 1: Run full typecheck**

```bash
cd family-app && npm run typecheck
```

Fix any errors.

**Step 2: Run protocol test suite** (ensure nothing is broken)

```bash
cd /media/sf_MintAI/Signet && node node_modules/vitest/vitest.mjs run
```

Expected: All 477 tests pass.

**Step 3: Run protocol typecheck**

```bash
cd /media/sf_MintAI/Signet && node node_modules/typescript/bin/tsc --noEmit
```

**Step 4: Manual smoke test** the family app

```bash
cd family-app && npm run dev
```

Test the following flows:
1. Welcome screen → Create My Signet → Enter name → Child check (No) → Recovery phrase → Continue
2. Home screen shows QR code, name, Signet ID
3. My Family tab shows empty state
4. Settings → View recovery phrase → Theme toggle → Export
5. Add (+) → verify scan/show QR/enter ID options render

**Step 5: Update CLAUDE.md** with family app info

Add to the Port Allocation section:
```
- **5175** — My Signet family app (HTTPS, self-signed cert)
```

Add to the Project Structure section:
```
├── family-app/   — My Signet family app (React + Vite + TypeScript)
```

**Step 6: Final commit**

```bash
git add -A
git commit -m "feat(family-app): complete My Signet family app — onboarding, home, family, Signet Me, settings"
```

**Step 7: Push**

```bash
git push
```
