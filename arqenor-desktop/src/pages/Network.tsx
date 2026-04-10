import { useEffect, useState, useCallback, useRef } from 'react'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import { ScanLine, Wifi, WifiOff, RotateCcw, Clock, AlertTriangle, Info } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { RiskBadge } from '@/components/ui/badge'
import { startNetworkScan, getVpnStatus } from '@/lib/commands'
import type { HostInfo, VpnInfo, Anomaly } from '@/lib/types'

const RESCAN_INTERVAL_S = 5 * 60 // 5 minutes

const ANOMALY_STYLE: Record<string, string> = {
  high:   'text-high   bg-high/5   border-high/25',
  medium: 'text-medium bg-medium/5 border-medium/25',
  info:   'text-accent bg-accent/5 border-accent/20',
}
const ANOMALY_ICON: Record<string, React.ReactNode> = {
  high:   <AlertTriangle className="size-3 shrink-0" />,
  medium: <AlertTriangle className="size-3 shrink-0" />,
  info:   <Info          className="size-3 shrink-0" />,
}

function AnomalyList({ anomalies }: { anomalies: Anomaly[] }) {
  if (anomalies.length === 0) return <span className="text-text-dim">—</span>
  return (
    <div className="flex flex-col gap-0.5">
      {anomalies.map((a, i) => (
        <div
          key={i}
          className={`flex items-center gap-1 rounded px-1.5 py-0.5 border text-[10px] font-medium ${ANOMALY_STYLE[a.severity] ?? ANOMALY_STYLE.info}`}
        >
          {ANOMALY_ICON[a.severity]}
          <span>{a.message}</span>
        </div>
      ))}
    </div>
  )
}

const PORT_NAMES: Record<number, string> = {
  21:   'ftp',
  22:   'ssh',
  23:   'telnet',
  25:   'smtp',
  53:   'dns',
  80:   'http',
  110:  'pop3',
  135:  'msrpc',
  139:  'netbios',
  443:  'https',
  445:  'smb',
  1433: 'mssql',
  3306: 'mysql',
  3389: 'rdp',
  5900: 'vnc',
  8080: 'http-alt',
  8443: 'https-alt',
}

const OS_STYLE: Record<string, string> = {
  Windows: 'text-[#5b9bd5]',
  Linux:   'text-[#ff8c00]',
  Router:  'text-low',
  Unknown: 'text-text-muted',
}

function sortHosts(hosts: HostInfo[]): HostInfo[] {
  const riskOrd: Record<string, number> = { High: 3, Medium: 2, Low: 1, Normal: 0 }
  return [...hosts].sort((a, b) =>
    (riskOrd[b.risk] ?? 0) - (riskOrd[a.risk] ?? 0) || a.ip.localeCompare(b.ip),
  )
}

export default function Network() {
  const [hosts,       setHosts]       = useState<HostInfo[]>([])
  const [vpn,         setVpn]         = useState<VpnInfo | null>(null)
  const [scanning,    setScanning]    = useState(false)
  const [subnetLabel, setSubnetLabel] = useState<string>('detecting…')
  const [elapsed,     setElapsed]     = useState(0)
  const [nextIn,      setNextIn]      = useState<number | null>(null)

  // Buffers / refs
  const unlistenRef   = useRef<UnlistenFn[]>([])
  const elapsedTimer  = useRef<ReturnType<typeof setInterval> | null>(null)
  const countdownTimer = useRef<ReturnType<typeof setInterval> | null>(null)
  const newHostsBuf   = useRef<HostInfo[]>([])  // collect incoming hosts without re-render storm
  const flushTimer    = useRef<ReturnType<typeof setInterval> | null>(null)

  const stopTimers = () => {
    ;[elapsedTimer, flushTimer].forEach(r => {
      if (r.current) { clearInterval(r.current); r.current = null }
    })
    unlistenRef.current.forEach(u => u())
    unlistenRef.current = []
  }

  const startCountdown = useCallback(() => {
    setNextIn(RESCAN_INTERVAL_S)
    if (countdownTimer.current) clearInterval(countdownTimer.current)
    countdownTimer.current = setInterval(() => {
      setNextIn(prev => {
        if (prev === null || prev <= 1) return null
        return prev - 1
      })
    }, 1000)
  }, [])

  const scan = useCallback(async (keepExisting = false) => {
    stopTimers()
    if (countdownTimer.current) { clearInterval(countdownTimer.current); countdownTimer.current = null }
    setNextIn(null)
    setScanning(true)
    setElapsed(0)
    newHostsBuf.current = []
    if (!keepExisting) setHosts([])

    const scanStart = Date.now()
    elapsedTimer.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - scanStart) / 1000))
    }, 1000)

    // Flush incoming hosts to state every 500 ms to avoid per-host re-renders
    flushTimer.current = setInterval(() => {
      if (newHostsBuf.current.length > 0) {
        const batch = [...newHostsBuf.current]
        newHostsBuf.current = []
        setHosts(prev => sortHosts([...prev.filter(h => !batch.find(b => b.ip === h.ip)), ...batch]))
      }
    }, 500)

    const [hostUL, doneUL] = await Promise.all([
      listen<HostInfo>('network-host', e => {
        newHostsBuf.current.push(e.payload)
      }),
      listen<null>('network-scan-done', () => {
        stopTimers()
        // Final flush
        if (newHostsBuf.current.length > 0) {
          const last = [...newHostsBuf.current]
          newHostsBuf.current = []
          setHosts(prev => sortHosts([...prev.filter(h => !last.find(b => b.ip === h.ip)), ...last]))
        }
        setScanning(false)
        startCountdown()
      }),
    ])
    unlistenRef.current = [hostUL, doneUL]

    try {
      const label = await startNetworkScan()
      setSubnetLabel(label)
    } catch (e) {
      console.error('scan failed', e)
      stopTimers()
      setScanning(false)
    }
  }, [startCountdown])

  // Auto-rescan when countdown reaches 0
  useEffect(() => {
    if (nextIn === 0) scan(true)  // keep existing results while rescanning
  }, [nextIn, scan])

  // Mount: fetch VPN + kick off first scan immediately
  useEffect(() => {
    getVpnStatus().then(setVpn).catch(() => {})
    scan(false)
    return () => {
      stopTimers()
      if (countdownTimer.current) clearInterval(countdownTimer.current)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const flagged = hosts.filter(h => h.risk !== 'Normal').length

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-3">
        <h1 className="text-xs font-bold tracking-widest text-accent text-glow-accent">
          NETWORK SCAN
        </h1>
        <span className="text-xs text-text-muted">{subnetLabel}</span>
        <div className="flex-1" />

        {/* VPN indicator */}
        {vpn ? (
          <div className="flex items-center gap-1.5 rounded border border-low/30 bg-low/5 px-2.5 py-1">
            <Wifi className="size-3 text-low" />
            <span className="text-xs text-low font-medium">{vpn.name}</span>
            <span className="text-[10px] text-text-muted">{vpn.tunnel}</span>
          </div>
        ) : (
          <div className="flex items-center gap-1.5 px-2 py-1 text-text-muted">
            <WifiOff className="size-3.5" />
            <span className="text-xs">No VPN</span>
          </div>
        )}

        {/* Status */}
        {scanning ? (
          <div className="flex items-center gap-2 rounded border border-accent/30 bg-accent/5 px-3 py-1">
            <ScanLine className="size-3 text-accent animate-pulse" />
            <span className="text-xs text-accent">{elapsed}s</span>
            <span className="text-xs text-text-muted">{hosts.length} found</span>
          </div>
        ) : hosts.length > 0 ? (
          <div className="flex items-center gap-1.5 text-text-muted">
            <span className="text-xs">{hosts.length} hosts · {flagged} flagged</span>
            {nextIn !== null && (
              <div className="flex items-center gap-1 ml-2 text-text-dim">
                <Clock className="size-3" />
                <span className="text-[10px]">
                  rescan in {nextIn >= 60
                    ? `${Math.floor(nextIn / 60)}m${nextIn % 60 > 0 ? `${nextIn % 60}s` : ''}`
                    : `${nextIn}s`}
                </span>
              </div>
            )}
          </div>
        ) : null}

        {/* Manual rescan */}
        <Button
          variant="outline"
          size="sm"
          onClick={() => scan(false)}
          disabled={scanning}
        >
          <RotateCcw className={`size-3.5 ${scanning ? 'animate-spin' : ''}`} />
          Rescan
        </Button>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {!scanning && hosts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
            <ScanLine className="size-10 opacity-20 animate-pulse" strokeWidth={1} />
            <p className="text-sm text-text-muted">Starting scan…</p>
          </div>
        ) : (
          <table className="w-full text-xs border-collapse">
            <thead className="sticky top-0 bg-surface z-10">
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-44">Host</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-24">Risk</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-24">OS</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-72">Open Ports</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium">Anomalies</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map(h => (
                <tr
                  key={h.ip}
                  className="data-row border-b border-border/50 hover:bg-surface-elevated/40 transition-colors"
                >
                  {/* Host cell: IP + hostname + NEW badge */}
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <div>
                        <div className="flex items-center gap-1.5">
                          <span className="font-medium text-text">{h.ip}</span>
                          {h.is_new && (
                            <span className="px-1 py-0 rounded text-[9px] font-bold bg-high/10 text-high border border-high/30 uppercase">
                              new
                            </span>
                          )}
                        </div>
                        {h.hostname && (
                          <span className="text-[10px] text-text-muted">{h.hostname}</span>
                        )}
                      </div>
                    </div>
                  </td>

                  <td className="px-4 py-2.5"><RiskBadge risk={h.risk} /></td>

                  <td className={`px-4 py-2.5 font-medium ${OS_STYLE[h.os] ?? 'text-text-muted'}`}>
                    {h.os}
                  </td>

                  {/* Ports */}
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {h.ports.map(p => (
                        <span
                          key={p}
                          className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium bg-surface-elevated border border-border"
                        >
                          <span className="text-text">{p}</span>
                          {PORT_NAMES[p] && (
                            <span className="text-text-muted">/{PORT_NAMES[p]}</span>
                          )}
                        </span>
                      ))}
                      {h.ports.length === 0 && (
                        <span className="text-text-dim italic">no open ports</span>
                      )}
                    </div>
                  </td>

                  {/* Anomalies */}
                  <td className="px-4 py-2.5">
                    <AnomalyList anomalies={h.anomalies} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
