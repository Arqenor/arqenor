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

// ── Incidents ────────────────────────────────────────────────────────────────

export interface Incident {
  id: string
  score: number
  severity: Severity
  attack_ids: string[]
  alerts: Alert[]
  summary: string
  pid: number | null
  first_seen: string
  last_seen: string
  is_closed: boolean
}

// ── Memory Forensics ─────────────────────────────────────────────────────────

export type MemoryAnomalyKind = 'AnonymousExecutable' | 'ProcessHollowing' | 'ExecutableHeap'

export interface MemoryAnomaly {
  kind: MemoryAnomalyKind
  base: number
  size: number
  protect: number
  disk_path: string | null
  mismatch: string | null
}

export interface MemoryScanResult {
  pid: number
  image_path: string
  total_regions: number
  suspicious: MemoryAnomaly[]
}

export interface NtdllHookResult {
  function_name: string
  is_hooked: boolean
  hook_type: string | null
}

export interface ByovdAlert {
  driver_name: string
  driver_path: string
  sha256: string
  vuln_name: string
  cve: string | null
}

// ── IOC Database ─────────────────────────────────────────────────────────────

export interface IocStats {
  sha256_count: number
  md5_count: number
  ip_count: number
  domain_count: number
  url_count: number
  total: number
  last_updated: string | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function kindLabel(kind: PersistenceKind): string {
  if (typeof kind === 'string') return kind
  return `Unknown(${kind.Unknown})`
}

export const RISK_ORDER: Record<RiskLevel | HostRisk, number> = {
  Critical: 4, High: 3, Medium: 2, Low: 1, Normal: 0,
}
