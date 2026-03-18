import { fromMnemonic, fromNsec } from 'nsec-tree'
import { derivePersona } from 'nsec-tree/persona'
import type { TreeRoot, Persona } from 'nsec-tree'

/** Purpose strings for signet's two required personas. */
export const NATURAL_PERSON_PERSONA = 'natural-person'
export const ANONYMOUS_PERSONA = 'persona'

/** A signet identity backed by an nsec-tree derivation tree. */
export interface SignetIdentity {
  readonly root: TreeRoot
  readonly naturalPerson: Persona
  readonly persona: Persona
  readonly mnemonic?: string
}

function deriveRequiredPersonas(root: TreeRoot): { naturalPerson: Persona; persona: Persona } {
  const naturalPerson = derivePersona(root, NATURAL_PERSON_PERSONA)
  const persona = derivePersona(root, ANONYMOUS_PERSONA)
  return { naturalPerson, persona }
}

/**
 * Create a signet identity from a BIP-39 mnemonic.
 * Derives the tree root via nsec-tree's `fromMnemonic()` (path m/44'/1237'/727'/0'/0'),
 * then derives both required personas.
 */
export function createSignetIdentity(mnemonic: string, passphrase?: string): SignetIdentity {
  const root = fromMnemonic(mnemonic, passphrase)
  const { naturalPerson, persona } = deriveRequiredPersonas(root)
  return { root, naturalPerson, persona, mnemonic }
}

/**
 * Create a signet identity from an existing nsec.
 * Wraps the nsec through nsec-tree's HMAC separation layer,
 * then derives both required personas.
 */
export function createSignetIdentityFromNsec(nsec: string | Uint8Array): SignetIdentity {
  const root = fromNsec(nsec)
  const { naturalPerson, persona } = deriveRequiredPersonas(root)
  return { root, naturalPerson, persona }
}
