import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, Cpu, Network, DatabaseZap, ShieldAlert, Wifi, WifiOff } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardValue } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { RiskBadge } from '@/components/ui/badge'
import { getProcesses, getPersistence, getVpnStatus } from '@/lib/commands'
import type { ProcessRow, PersistenceEntry, VpnInfo } from '@/lib/types'

interface Stats {
  total:    number
  critical: number
  high:     number
  medium:   number
  low:      number
}

function computeStats(rows: ProcessRow[]): Stats {
  return rows.reduce(
    (acc, r) => ({
      total:    acc.total + 1,
      critical: acc.critical + (r.risk === 'Critical' ? 1 : 0),
      high:     acc.high     + (r.risk === 'High'     ? 1 : 0),
      medium:   acc.medium   + (r.risk === 'Medium'   ? 1 : 0),
      low:      acc.low      + (r.risk === 'Low'      ? 1 : 0),
    }),
    { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
  )
}

export default function Dashboard() {
  const [processes,   setProcesses]   = useState<ProcessRow[]>([])
  const [persistence, setPersistence] = useState<PersistenceEntry[]>([])
  const [vpn,         setVpn]         = useState<VpnInfo | null>(null)
  const [loading,     setLoading]     = useState(true)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const [procs, pers, vpnInfo] = await Promise.all([
        getProcesses(),
        getPersistence(),
        getVpnStatus(),
      ])
      setProcesses(procs)
      setPersistence(pers)
      setVpn(vpnInfo)
      setLastRefresh(new Date())
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const stats   = computeStats(processes)
  const flagged = stats.critical + stats.high + stats.medium

  const threats = [
    ...processes.filter(r => r.risk === 'Critical' || r.risk === 'High').slice(0, 5),
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <div>
          <h1 className="text-base font-bold tracking-widest text-accent text-glow-accent">
            SYSTEM OVERVIEW
          </h1>
          {lastRefresh && (
            <p className="text-[11px] text-text-muted mt-0.5">
              Last scan — {lastRefresh.toLocaleTimeString()}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          {vpn ? (
            <div className="flex items-center gap-1.5 rounded border border-low/30 bg-low/5 px-3 py-1.5">
              <Wifi className="size-3 text-low" />
              <span className="text-xs text-low font-medium">{vpn.name}</span>
              <span className="text-[10px] text-text-muted">{vpn.tunnel}</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 rounded border border-border px-3 py-1.5">
              <WifiOff className="size-3 text-text-muted" />
              <span className="text-xs text-text-muted">No VPN</span>
            </div>
          )}
          <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
            <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Stat cards */}
        <div className="grid grid-cols-4 gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Processes</CardTitle>
              <Cpu className="size-4 text-text-muted" strokeWidth={1.5} />
            </CardHeader>
            <CardValue>{stats.total}</CardValue>
            <p className="text-[11px] text-text-muted mt-1">running</p>
          </Card>

          <Card glow={flagged > 0}>
            <CardHeader>
              <CardTitle>Flagged</CardTitle>
              <ShieldAlert className="size-4 text-high" strokeWidth={1.5} />
            </CardHeader>
            <CardValue className={flagged > 0 ? 'text-high' : undefined}>{flagged}</CardValue>
            <p className="text-[11px] text-text-muted mt-1">need review</p>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Persistence</CardTitle>
              <DatabaseZap className="size-4 text-text-muted" strokeWidth={1.5} />
            </CardHeader>
            <CardValue>{persistence.length}</CardValue>
            <p className="text-[11px] text-text-muted mt-1">startup entries</p>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>New entries</CardTitle>
              <DatabaseZap className="size-4 text-medium" strokeWidth={1.5} />
            </CardHeader>
            <CardValue className={persistence.filter(p => p.is_new).length > 0 ? 'text-medium' : undefined}>
              {persistence.filter(p => p.is_new).length}
            </CardValue>
            <p className="text-[11px] text-text-muted mt-1">since last scan</p>
          </Card>
        </div>

        {/* Bottom row */}
        <div className="grid grid-cols-2 gap-4">
          {/* Risk distribution */}
          <Card>
            <CardHeader>
              <CardTitle>Risk Distribution</CardTitle>
            </CardHeader>
            <div className="space-y-2.5">
              {([
                { label: 'Critical', count: stats.critical, color: 'bg-critical', textColor: 'text-critical' },
                { label: 'High',     count: stats.high,     color: 'bg-high',     textColor: 'text-high'     },
                { label: 'Medium',   count: stats.medium,   color: 'bg-medium',   textColor: 'text-medium'   },
                { label: 'Low',      count: stats.low,      color: 'bg-low',      textColor: 'text-low'      },
              ] as const).map(({ label, count, color, textColor }) => (
                <div key={label} className="flex items-center gap-3">
                  <span className={`w-14 text-right text-xs font-medium ${textColor}`}>{label}</span>
                  <div className="flex-1 h-1.5 rounded bg-surface-elevated overflow-hidden">
                    <div
                      className={`h-full rounded transition-all duration-500 ${color}`}
                      style={{ width: stats.total ? `${(count / stats.total) * 100}%` : '0%' }}
                    />
                  </div>
                  <span className={`w-6 text-right text-xs font-bold ${count > 0 ? textColor : 'text-text-muted'}`}>
                    {count}
                  </span>
                </div>
              ))}
            </div>
          </Card>

          {/* Recent threats */}
          <Card>
            <CardHeader>
              <CardTitle>Recent Threats</CardTitle>
              <Network className="size-4 text-text-muted" strokeWidth={1.5} />
            </CardHeader>
            {threats.length === 0 ? (
              <p className="text-sm text-text-muted py-4 text-center">No active threats detected</p>
            ) : (
              <div className="space-y-1.5">
                {threats.map(t => (
                  <div key={t.info.pid} className="flex items-center justify-between gap-3 rounded p-2 bg-surface-elevated">
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-text truncate">{t.info.name}</p>
                      {t.info.exe_path && (
                        <p className="text-[10px] text-text-muted truncate">{t.info.exe_path}</p>
                      )}
                    </div>
                    <RiskBadge risk={t.risk} />
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}
