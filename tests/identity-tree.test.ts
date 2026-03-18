import { describe, it, expect } from 'vitest'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import {
  createSignetIdentity,
  createSignetIdentityFromNsec,
} from '../src/identity-tree.js'

const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

describe('createSignetIdentity', () => {
  it('returns SignetIdentity with both required personas', () => {
    const identity = createSignetIdentity(TEST_MNEMONIC)
    expect(identity.root).toBeDefined()
    expect(identity.root.masterPubkey).toMatch(/^npub1/)
    expect(identity.naturalPerson).toBeDefined()
    expect(identity.naturalPerson.name).toBe('natural-person')
    expect(identity.naturalPerson.identity.npub).toMatch(/^npub1/)
    expect(identity.persona).toBeDefined()
    expect(identity.persona.name).toBe('persona')
    expect(identity.persona.identity.npub).toMatch(/^npub1/)
    expect(identity.mnemonic).toBe(TEST_MNEMONIC)
    identity.root.destroy()
  })

  it('produces deterministic output for same mnemonic', () => {
    const a = createSignetIdentity(TEST_MNEMONIC)
    const b = createSignetIdentity(TEST_MNEMONIC)
    expect(a.naturalPerson.identity.npub).toBe(b.naturalPerson.identity.npub)
    expect(a.persona.identity.npub).toBe(b.persona.identity.npub)
    expect(a.root.masterPubkey).toBe(b.root.masterPubkey)
    a.root.destroy()
    b.root.destroy()
  })

  it('produces different output for different mnemonics', () => {
    const other = generateMnemonic(wordlist)
    const a = createSignetIdentity(TEST_MNEMONIC)
    const b = createSignetIdentity(other)
    expect(a.naturalPerson.identity.npub).not.toBe(b.naturalPerson.identity.npub)
    a.root.destroy()
    b.root.destroy()
  })

  it('passphrase changes derived identity', () => {
    const a = createSignetIdentity(TEST_MNEMONIC)
    const b = createSignetIdentity(TEST_MNEMONIC, 'my-passphrase')
    expect(a.naturalPerson.identity.npub).not.toBe(b.naturalPerson.identity.npub)
    expect(a.root.masterPubkey).not.toBe(b.root.masterPubkey)
    a.root.destroy()
    b.root.destroy()
  })

  it('natural person and persona npubs differ from each other and from master', () => {
    const identity = createSignetIdentity(TEST_MNEMONIC)
    const npNpub = identity.naturalPerson.identity.npub
    const pNpub = identity.persona.identity.npub
    const masterNpub = identity.root.masterPubkey
    expect(npNpub).not.toBe(pNpub)
    expect(npNpub).not.toBe(masterNpub)
    expect(pNpub).not.toBe(masterNpub)
    identity.root.destroy()
  })
})

describe('createSignetIdentityFromNsec', () => {
  it('returns SignetIdentity with both personas from nsec string', () => {
    const mnemonic = createSignetIdentity(TEST_MNEMONIC)
    const nsec = mnemonic.naturalPerson.identity.nsec
    mnemonic.root.destroy()

    const identity = createSignetIdentityFromNsec(nsec)
    expect(identity.root).toBeDefined()
    expect(identity.naturalPerson).toBeDefined()
    expect(identity.persona).toBeDefined()
    expect(identity.mnemonic).toBeUndefined()
    identity.root.destroy()
  })

  it('returns SignetIdentity from raw Uint8Array private key', () => {
    const mnemonic = createSignetIdentity(TEST_MNEMONIC)
    const privateKey = new Uint8Array(mnemonic.naturalPerson.identity.privateKey)
    mnemonic.root.destroy()

    const identity = createSignetIdentityFromNsec(privateKey)
    expect(identity.root).toBeDefined()
    expect(identity.naturalPerson).toBeDefined()
    expect(identity.persona).toBeDefined()
    identity.root.destroy()
  })

  it('produces deterministic output for same nsec', () => {
    const src = createSignetIdentity(TEST_MNEMONIC)
    const nsec = src.naturalPerson.identity.nsec
    src.root.destroy()

    const a = createSignetIdentityFromNsec(nsec)
    const b = createSignetIdentityFromNsec(nsec)
    expect(a.naturalPerson.identity.npub).toBe(b.naturalPerson.identity.npub)
    expect(a.persona.identity.npub).toBe(b.persona.identity.npub)
    a.root.destroy()
    b.root.destroy()
  })
})
