import { useState, useEffect, useCallback } from 'react';
import type { AppPreferences, SecurityTier } from '../types';
import { TIER_WORD_COUNT } from '../types';
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

  const setSecurityTier = useCallback(async (tier: SecurityTier) => {
    const updated = { ...preferences, securityTier: tier };
    setPreferences(updated);
    await db.savePreferences(updated);
  }, [preferences]);

  const setRelayUrl = useCallback(async (url: string) => {
    const updated = { ...preferences, relayUrl: url };
    setPreferences(updated);
    await db.savePreferences(updated);
  }, [preferences]);

  const setPowerMode = useCallback(async (enabled: boolean) => {
    const updated = { ...preferences, powerMode: enabled };
    setPreferences(updated);
    await db.savePreferences(updated);
  }, [preferences]);

  const securityTier: SecurityTier = preferences.securityTier ?? 'basic';
  const wordCount = TIER_WORD_COUNT[securityTier];
  const powerMode = preferences.powerMode ?? false;

  return { preferences, loading, setTheme, securityTier, wordCount, setSecurityTier, setRelayUrl, setPowerMode, powerMode };
}
