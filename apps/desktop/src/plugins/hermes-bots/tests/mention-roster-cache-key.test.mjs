import assert from 'node:assert/strict'
import test from 'node:test'

import { readCachedUnionRoster } from '../../../sdk/roster-cache.mjs'

const ROSTER_KEY = ['hermes-bots', 'roster']
const REMOTE_ROSTER = {
  fetchedAt: 20,
  profiles: [
    { name: 'default', connectionId: 'local', connectionKind: 'local' },
    {
      name: 'default',
      handle: 'default-vera',
      connectionId: 'vera',
      connectionKind: 'ssh',
      remoteSource: true,
      sourceScoped: true
    }
  ]
}

function makeQueryClient() {
  const entries = new Map()
  const keyOf = key => JSON.stringify(key)

  return {
    setQueryData(key, value) {
      entries.set(keyOf(key), { key, value })
    },
    getQueryData(key) {
      return entries.get(keyOf(key))?.value
    },
    getQueriesData({ queryKey }) {
      return [...entries.values()]
        .filter(({ key }) => queryKey.every((part, index) => key[index] === part))
        .map(({ key, value }) => [key, value])
    }
  }
}

test('reads the active connection roster from its suffixed cache key', () => {
  const client = makeQueryClient()
  client.setQueryData([...ROSTER_KEY, 'local'], REMOTE_ROSTER)

  assert.equal(client.getQueryData(ROSTER_KEY), undefined)
  assert.equal(readCachedUnionRoster(client, ROSTER_KEY, 'local'), REMOTE_ROSTER)
})

test('preserves remote mention handles from the connection-scoped roster', () => {
  const client = makeQueryClient()
  client.setQueryData([...ROSTER_KEY, 'local'], REMOTE_ROSTER)

  const roster = readCachedUnionRoster(client, ROSTER_KEY, 'local')
  assert.ok(roster.profiles.some(profile => profile.handle === 'default-vera'))
})

test('falls back to the freshest valid roster when the active entry is absent', () => {
  const client = makeQueryClient()
  const older = { fetchedAt: 10, profiles: [{ name: 'older' }] }
  const newer = { fetchedAt: 30, profiles: [{ name: 'newer', handle: 'newer-remote' }] }
  client.setQueryData([...ROSTER_KEY, 'old-connection'], older)
  client.setQueryData([...ROSTER_KEY, 'new-connection'], newer)

  assert.equal(readCachedUnionRoster(client, ROSTER_KEY, 'local'), newer)
})

test('fails closed for cold, legacy, and throwing query clients', () => {
  assert.equal(readCachedUnionRoster(null, ROSTER_KEY, 'local'), null)
  assert.equal(readCachedUnionRoster({ getQueryData: () => undefined }, ROSTER_KEY, 'local'), null)
  assert.equal(
    readCachedUnionRoster({ getQueryData: () => { throw new Error('cache unavailable') } }, ROSTER_KEY, 'local'),
    null
  )
})
