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

export interface ScoreFactor {
  name: string
  points: number
  attack_id: string | null
}

export interface ProcessRow {
  info: ProcessInfo
  risk: RiskLevel
  score: number
  factors: ScoreFactor[]
}

// ── Persistence ───────────────────────────────────────────────────────────────

export type PersistenceKind =
  | 'RegistryRun' | 'ScheduledTask' | 'WindowsService'
  | 'WmiSubscription' | 'ComHijacking' | 'DllSideloading'
  | 'BitsJob' | 'AppInitDll' | 'IfeoHijack' | 'AccessibilityHijack'
  | 'PrintMonitor' | 'LsaProvider' | 'NetshHelper'
  | 'SystemdUnit' | 'Cron' | 'RcLocal' | 'LdPreload'
  | 'LaunchDaemon' | 'LaunchAgent'
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

export interface Anomaly {
  severity: 'high' | 'medium' | 'info'
  message:  string
}

export interface HostInfo {
  ip:        string
  hostname:  string | null
  ports:     number[]
  risk:      HostRisk
  os:        OsGuess
  is_new:    boolean
  anomalies: Anomaly[]
}

export interface VpnInfo {
  name:   string
  tunnel: string
}

// ── Alerts ────────────────────────────────────────────────────────────────────

export type Severity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical'

export interface Alert {
  id: string
  severity: Severity
  kind: string
  message: string
  occurred_at: string   // ISO datetime from Rust chrono
  metadata: Record<string, string>
  rule_id: string | null
  attack_id: string | null
}

// ── ETW Stream ────────────────────────────────────────────────────────────────

export interface EtwEvent {
  provider_label: string
  provider_guid:  string
  event_id:       number
  pid:            number
  tid:            number
  timestamp:      string   // ISO-8601
  level:          number
  keyword:        number
  data_size:      number
  description:    string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function kindLabel(kind: PersistenceKind): string {
  if (typeof kind === 'string') return kind
  return `Unknown(${kind.Unknown})`
}

export const RISK_ORDER: Record<RiskLevel | HostRisk, number> = {
  Critical: 4, High: 3, Medium: 2, Low: 1, Normal: 0,
}
