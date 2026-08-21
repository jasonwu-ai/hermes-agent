export interface CachedUnionRoster {
  profiles: unknown[]
  fetchedAt?: number
  [key: string]: unknown
}

export interface RosterQueryClient {
  getQueryData(key: unknown[]): unknown
  getQueriesData?(filters: { queryKey: unknown[] }): Array<[unknown[], unknown]>
}

export function readCachedUnionRoster(
  queryClient: RosterQueryClient | null | undefined,
  rosterKey: unknown[],
  connectionId: string | null | undefined
): CachedUnionRoster | null
