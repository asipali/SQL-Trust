/**
 * SQL-TRUST Investigation API Client Service
 * Handles data fetching, parameter mapping, and response normalization.
 */
import axios from 'axios'
import { InvestigationCase } from '../types/investigation'
import { normalizeCasesResponse } from '../utils/normalizeCases'

export class InvestigationService {
  /**
   * Fetches investigation cases with optional filtering, applying normalization defensively.
   */
  static async fetchCases(apiBase: string, statusFilter?: string): Promise<InvestigationCase[]> {
    const params = new URLSearchParams()
    if (statusFilter && statusFilter !== 'ALL') {
      params.append('status', statusFilter)
    }

    const queryString = params.toString()
    const url = queryString
      ? `${apiBase}/api/v1/investigations?${queryString}`
      : `${apiBase}/api/v1/investigations`

    const headers: Record<string, string> = {}
    try {
      const saved = localStorage.getItem('sqltrust_session')
      if (saved) {
        const session = JSON.parse(saved)
        if (session?.access_token) {
          headers['Authorization'] = `Bearer ${session.access_token}`
        }
      }
    } catch {}

    const response = await axios.get(url, { headers })
    return normalizeCasesResponse(response.data)
  }

  /**
   * Fetches full case details including evidence links, status history, and notes.
   */
  static async fetchCaseDetail(apiBase: string, caseIdentifier: string): Promise<InvestigationCase> {
    const headers: Record<string, string> = {}
    try {
      const saved = localStorage.getItem('sqltrust_session')
      if (saved) {
        const session = JSON.parse(saved)
        if (session?.access_token) {
          headers['Authorization'] = `Bearer ${session.access_token}`
        }
      }
    } catch {}

    const response = await axios.get(
      `${apiBase}/api/v1/investigations/${encodeURIComponent(caseIdentifier)}`,
      { headers }
    )
    return response.data as InvestigationCase
  }
}
