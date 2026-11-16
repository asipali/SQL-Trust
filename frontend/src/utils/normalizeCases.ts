/**
 * SQL-TRUST Investigation Cases Response Normalization Layer
 * Defensively extracts and validates InvestigationCase[] from various API payload structures.
 */
import { InvestigationCase } from '../types/investigation'

export type RawCasesApiResponse =
  | InvestigationCase[]
  | { items: InvestigationCase[]; total?: number; page?: number; page_size?: number }
  | { cases: InvestigationCase[]; total?: number }
  | unknown

/**
 * Normalizes API response into a strictly-typed array of InvestigationCase.
 *
 * Supported formats:
 * 1. Direct array: `[ ...cases ]`
 * 2. Paginated object: `{ items: [ ...cases ], total, page, page_size }`
 * 3. Wrapped object: `{ cases: [ ...cases ] }`
 *
 * Throws an explicit Error on invalid, null, or malformed payloads.
 */
export function normalizeCasesResponse(response: RawCasesApiResponse): InvestigationCase[] {
  if (response === null || response === undefined) {
    throw new Error('Invalid investigation cases API response: null or undefined payload received.')
  }

  // 1. Direct array response
  if (Array.isArray(response)) {
    return response as InvestigationCase[]
  }

  // 2. Object responses with nested array
  if (typeof response === 'object' && response !== null) {
    const record = response as Record<string, unknown>

    if (Array.isArray(record.items)) {
      return record.items as InvestigationCase[]
    }

    if (Array.isArray(record.cases)) {
      return record.cases as InvestigationCase[]
    }
  }

  console.error('[SQL-TRUST] Unrecognized investigation API response structure:', response)
  throw new Error(
    'Invalid investigation cases API response structure: expected array or object containing "items" or "cases".'
  )
}
