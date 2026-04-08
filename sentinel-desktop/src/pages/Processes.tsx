import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, Search, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { RiskBadge } from '@/components/ui/badge'
import { getProcesses } from '@/lib/commands'
import type { ProcessRow } from '@/lib/types'

export default function Processes() {
  const [rows,        setRows]        = useState<ProcessRow[]>([])
  const [filter,      setFilter]      = useState('')
  const [loading,     setLoading]     = useState(true)
  const [expandedPid, setExpandedPid] = useState<number | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    try { setRows(await getProcesses()) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const filtered = filter
    ? rows.filter(r =>
        r.info.name.toLowerCase().includes(filter.toLowerCase()) ||
        r.info.exe_path?.toLowerCase().includes(filter.toLowerCase()) ||
        String(r.info.pid).includes(filter),
      )
    : rows

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-3">
        <h1 className="text-xs font-bold tracking-widest text-accent text-glow-accent">
          PROCESSES
        </h1>
        <span className="text-xs text-text-muted">
          {filtered.length} / {rows.length}
        </span>
        <div className="flex-1" />
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-text-muted" />
          <Input
            placeholder="Filter by name, path, PID…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="pl-8 pr-8 text-xs"
          />
          {filter && (
            <button
              onClick={() => setFilter('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text"
            >
              <X className="size-3.5" />
            </button>
          )}
        </div>
        <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
          <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-xs border-collapse">
          <thead className="sticky top-0 bg-surface z-10">
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-text-muted font-medium w-16">PID</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Name</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium">Path</th>
              <th className="text-left px-4 py-2.5 text-text-muted font-medium w-24">User</th>
              <th className="text-right px-4 py-2.5 text-text-muted font-medium w-14">Score</th>
              <th className="text-right px-4 py-2.5 text-text-muted font-medium w-24">Risk</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(r => (
              <>
                <tr
                  key={r.info.pid}
                  className="data-row border-b border-border/50 hover:bg-surface-elevated/40 transition-colors"
                >
                  <td className="px-4 py-2 text-text-muted">{r.info.pid}</td>
                  <td className="px-4 py-2">
                    <span className={
                      r.risk === 'Critical' ? 'text-critical font-medium' :
                      r.risk === 'High'     ? 'text-high font-medium'     :
                      r.risk === 'Medium'   ? 'text-medium'               :
                      'text-text'
                    }>
                      {r.info.name}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-text-muted max-w-xs">
                    <span className="block truncate" title={r.info.exe_path ?? ''}>
                      {r.info.exe_path ?? <span className="text-text-dim italic">no path</span>}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-text-muted">{r.info.user ?? '—'}</td>
                  <td className="px-4 py-2 text-right">
                    {r.factors && r.factors.length > 0 ? (
                      <button
                        onClick={() => setExpandedPid(expandedPid === r.info.pid ? null : r.info.pid)}
                        className={`font-medium hover:text-accent transition-colors ${r.score > 0 ? 'text-text' : 'text-text-dim'}`}
                      >
                        {r.score}
                        <span className="ml-0.5 text-text-dim text-[10px]">▾</span>
                      </button>
                    ) : (
                      <span className={r.score > 0 ? 'text-text font-medium' : 'text-text-dim'}>{r.score}</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <RiskBadge risk={r.risk} />
                  </td>
                </tr>
                {expandedPid === r.info.pid && (
                  <tr key={`${r.info.pid}-factors`} className="bg-surface-elevated/60">
                    <td colSpan={6} className="px-8 py-2">
                      <div className="flex flex-col gap-1">
                        {r.factors.map((f, i) => (
                          <div key={i} className="flex items-center gap-3 text-[11px]">
                            <span className="text-high font-medium w-6 text-right">+{f.points}</span>
                            <span className="text-text-muted">{f.name}</span>
                            {f.attack_id && (
                              <span className="ml-auto px-1 py-0.5 rounded bg-surface border border-border text-accent font-mono text-[10px]">
                                {f.attack_id}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {filtered.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="text-center py-12 text-text-muted">
                  {filter ? 'No processes match your filter.' : 'No processes found.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
