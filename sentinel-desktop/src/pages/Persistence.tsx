import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, DatabaseZap, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { getPersistence } from '@/lib/commands'
import type { PersistenceEntry } from '@/lib/types'
import { kindLabel } from '@/lib/types'

const KIND_ACCENT: Record<string, string> = {
  RegistryRun:    'text-medium  border-medium/30  bg-medium/5',
  ScheduledTask:  'text-high    border-high/30    bg-high/5',
  WindowsService: 'text-accent  border-accent/30  bg-accent/5',
  StartupFolder:  'text-text    border-border     bg-surface-elevated',
  SystemdUnit:    'text-accent  border-accent/30  bg-accent/5',
  Cron:           'text-text    border-border     bg-surface-elevated',
  LaunchDaemon:   'text-high    border-high/30    bg-high/5',
  LaunchAgent:    'text-text    border-border     bg-surface-elevated',
}

export default function Persistence() {
  const [entries, setEntries] = useState<PersistenceEntry[]>([])
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    setLoading(true)
    try { setEntries(await getPersistence()) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const newEntries = entries.filter(e => e.is_new)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-3">
        <h1 className="text-xs font-bold tracking-widest text-accent text-glow-accent">
          PERSISTENCE
        </h1>
        <span className="text-xs text-text-muted">{entries.length} entries</span>
        {newEntries.length > 0 && (
          <div className="flex items-center gap-1.5 rounded border border-medium/30 bg-medium/5 px-2 py-1">
            <AlertTriangle className="size-3 text-medium" />
            <span className="text-xs text-medium font-medium">{newEntries.length} new</span>
          </div>
        )}
        <div className="flex-1" />
        <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
          <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {entries.length === 0 && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
            <DatabaseZap className="size-10 opacity-20" strokeWidth={1} />
            <p className="text-sm">No persistence entries detected</p>
          </div>
        ) : (
          <table className="w-full text-xs border-collapse">
            <thead className="sticky top-0 bg-surface z-10">
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-36">Type</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-48">Name</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium">Command</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium">Location</th>
                <th className="text-right px-4 py-2.5 text-text-muted font-medium w-16">New</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => {
                const kl = kindLabel(e.kind)
                return (
                  <tr
                    key={i}
                    className="data-row border-b border-border/50 hover:bg-surface-elevated/40 transition-colors"
                  >
                    <td className="px-4 py-2.5">
                      <span className={`risk-badge ${KIND_ACCENT[kl] ?? 'text-text-muted border-border bg-surface-elevated'}`}>
                        {kl}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-medium text-text">
                      <span className="block truncate max-w-[180px]" title={e.name}>
                        {e.name}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-text-muted font-mono">
                      <span className="block truncate max-w-xs" title={e.command}>
                        {e.command}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-text-muted">
                      <span className="block truncate max-w-xs" title={e.location}>
                        {e.location}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      {e.is_new && (
                        <Badge variant="accent" className="text-[9px]">NEW</Badge>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
