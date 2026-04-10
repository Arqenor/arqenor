import { invoke } from '@tauri-apps/api/core'
import type { Alert, ProcessRow, PersistenceEntry, VpnInfo } from './types'

export const getProcesses   = () => invoke<ProcessRow[]>('get_processes')
export const getPersistence = () => invoke<PersistenceEntry[]>('get_persistence')
export const getVpnStatus   = () => invoke<VpnInfo | null>('get_vpn_status')
export const getAlerts      = () => invoke<Alert[]>('get_alerts')

/** Starts a subnet scan. Returns the subnet label e.g. "192.168.1.x/24".
 *  Host results come via the "network-host" event.
 *  Scan completion fires "network-scan-done". */
export const startNetworkScan = () => invoke<string>('start_network_scan')
