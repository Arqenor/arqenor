import { invoke } from '@tauri-apps/api/core'
import type { ProcessRow, PersistenceEntry, VpnInfo } from './types'

export const getProcesses  = () => invoke<ProcessRow[]>('get_processes')
export const getPersistence = () => invoke<PersistenceEntry[]>('get_persistence')
export const getVpnStatus  = () => invoke<VpnInfo | null>('get_vpn_status')

/** Starts a subnet scan. Returns the subnet label e.g. "192.168.1.x/24".
 *  Host results come via the "network-host" event.
 *  Scan completion fires "network-scan-done". */
export const startNetworkScan = () => invoke<string>('start_network_scan')
