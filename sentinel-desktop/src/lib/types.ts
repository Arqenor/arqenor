// ── Process ──────────────────────────────────────────────────────────────────

export interface ProcessInfo {
  pid: number
  ppid: number
  name: string
  exe_path: string | null
  cmdline: string | null
  user: string | null
  sha256: string | null
  started_at: string | null
  loaded_modules: string[]
}

export type RiskLevel = 'Normal' | 'Low' | 'Medium' | 'High' | 'Critical'

export interface ProcessRow {
  info: ProcessInfo
  risk: RiskLevel
  score: number
}

// ── Persistence ───────────────────────────────────────────────────────────────

export type PersistenceKind =
  | 'RegistryRun'
  | 'ScheduledTask'
  | 'WindowsService'
  | 'SystemdUnit'
  | 'Cron'
  | 'RcLocal'
  | 'LdPreload'
  | 'LaunchDaemon'
  | 'LaunchAgent'
  | 'StartupFolder'
  | { Unknown: string }

export interface PersistenceEntry {
  kind: PersistenceKind
  name: string
  command: string
  location: string
  is_new: boolean
}

// ── Network ───────────────────────────────────────────────────────────────────

export type HostRisk = 'Normal' | 'Low' | 'Medium' | 'High'
export type OsGuess  = 'Windows' | 'Linux' | 'Router' | 'Unknown'

export interface HostInfo {
  ip:    string
  ports: number[]
  risk:  HostRisk
  os:    OsGuess
}

export interface VpnInfo {
  name:   string
  tunnel: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function kindLabel(kind: PersistenceKind): string {
  if (typeof kind === 'string') return kind
  return `Unknown(${kind.Unknown})`
}

export const RISK_ORDER: Record<RiskLevel | HostRisk, number> = {
  Critical: 4, High: 3, Medium: 2, Low: 1, Normal: 0,
}
