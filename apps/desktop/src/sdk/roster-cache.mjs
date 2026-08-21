/**
 * Read the current union roster from TanStack Query's connection-scoped cache.
 *
 * `useRoster()` stores snapshots under `[...rosterKey, connectionId]`. Prefer
 * the active connection's exact entry; when it is absent, select the freshest
 * valid snapshot across the roster-key family. Cold, legacy, or failing query
 * clients return null so callers can use their existing fallback path.
 */
export function readCachedUnionRoster(queryClient, rosterKey, connectionId) {
  if (!queryClient || typeof queryClient.getQueryData !== 'function') return null

  try {
    const exact = queryClient.getQueryData([...rosterKey, String(connectionId || 'local')])
    if (Array.isArray(exact?.profiles)) return exact

    if (typeof queryClient.getQueriesData !== 'function') return null

    let best = null
    for (const [, data] of queryClient.getQueriesData({ queryKey: rosterKey })) {
      if (
        Array.isArray(data?.profiles) &&
        (!best || Number(data.fetchedAt || 0) > Number(best.fetchedAt || 0))
      ) {
        best = data
      }
    }
    return best
  } catch {
    return null
  }
}
