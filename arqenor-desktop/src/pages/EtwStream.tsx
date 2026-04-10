import { useEffect, useRef, useState } from 'react'
import { Activity, RefreshCw, Pause, Play } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { invoke } from '@tauri-apps/api/core'
import type { EtwEvent } from '@/lib/types'

// ── Provider colour mapping ───────────────────────────────────────────────────

const PROVIDER_COLORS: Record<string, string> = {
  'PowerShell':    'text-high   border-high/30   bg-high/10',
  'Security-Audit':'text-critical border-critical/30 bg-critical/10',
  'WMI-Activity':  'text-high   border-high/30   bg-high/10',
  'TaskScheduler': 'text-medium border-medium/30 bg-medium/10',
  'Kernel-Process':'text-accent border-accent/30 bg-accent/10',
  'Kernel-Network':'text-accent border-accent/30 bg-accent/10',
  'Kernel-File':   'text-low    border-low/30    bg-low/10',
  'Kernel-Registry':'text-low   border-low/30    bg-low/10',
  'DNS-Client':    'text-text-muted border-border bg-surface',
}

const providerColor = (label: string) =>
  PROVIDER_COLORS[label] ?? 'text-text-muted border-border bg-surface'

// ── Level label ───────────────────────────────────────────────────────────────

const LEVEL_LABEL: Record<number, string> = {
  1: 'CRITICAL', 2: 'ERROR', 3: 'WARN', 4: 'INFO', 5: 'VERBOSE',
}

const levelLabel = (l: number) => LEVEL_LABEL[l] ?? `L${l}`

// ── High-value event IDs that merit highlighting ───────────────────────────────

const HIGH_VALUE_EVENTS = new Set([4104, 4698, 4702, 4720, 4732, 5861, 106])

// ── Providers for filter tabs ─────────────────────────────────────────────────

const PROVIDERS = [
  'All', 'PowerShell', 'Security-Audit', 'WMI-Activity', 'TaskScheduler',
  'Kernel-Process', 'Kernel-Network', 'Kernel-File', 'Kernel-Registry', 'DNS-Client',
] as const

type ProviderFilter = typeof PROVIDERS[number]

// ── Component ─────────────────────────────────────────────────────────────────

export default function EtwStream() {
  const [events, setEvents]   = useState<EtwEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [paused, setPaused]   = useState(false)
  const [filter, setFilter]   = useState<ProviderFilter>('All')

  const pausedRef = useRef(paused)
  pausedRef.current = paused

  const refresh = async () => {
    if (pausedRef.current) return
    setLoading(true)
    try {
      const data = await invoke<EtwEvent[]>('get_etw_events')
      setEvents(data)
    } finally {
      setLoading(false)
    }
  }

  // Auto-refresh every 3 s
  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 3_000)
    return () => clearInterval(id)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = filter === 'All'
    ? events
    : events.filter(e => e.provider_label === filter)

  const providerCounts = events.reduce((acc, e) => {
    acc[e.provider_label] = (acc[e.provider_label] ?? 0) + 1
    return acc
  }, {} as Record<string, number>)

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-3">
        <Activity className="size-3.5 text-accent" strokeWidth={1.5} />
        <h1 className="text-xs font-bold tracking-widest text-accent text-glow-accent">
          ETW STREAM
        </h1>
        <span className="text-xs text-text-muted">{filtered.length} events</span>
        {events.length === 0 && !loading && (
          <span className="text-[10px] text-medium font-mono">
            — requires Administrator privileges
          </span>
        )}
        <div className="flex-1" />
        <Button
          variant="ghost" size="sm"
          onClick={() => setPaused(p => !p)}
          className={paused ? 'text-medium' : 'text-text-muted'}
        >
          {paused
            ? <><Play  className="size-3.5" /> Resume</>
            : <><Pause className="size-3.5" /> Pause</>}
        </Button>
        <Button variant="ghost" size="sm" onClick={refresh} disabled={loading || paused}>
          <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Provider filter tabs */}
      <div className="flex items-center gap-1 px-6 py-2 border-b border-border bg-surface overflow-x-auto">
        {PROVIDERS.map(prov => (
          <button
            key={prov}
            onClick={() => setFilter(prov)}
            className={`shrink-0 px-3 py-1 rounded text-xs font-medium transition-all border ${
              filter === prov
                ? prov === 'All'
                  ? 'border-accent/30 bg-accent/10 text-accent'
                  : providerColor(prov)
                : 'border-transparent text-text-muted hover:text-text hover:border-border'
            }`}
          >
            {prov}
            {prov !== 'All' && providerCounts[prov] ? (
              <span className="ml-1.5 text-[10px] opacity-70">{providerCounts[prov]}</span>
            ) : null}
          </button>
        ))}
      </div>

      {/* Event table */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
            <Activity className="size-10 opacity-20" strokeWidth={1} />
            <p className="text-sm">No ETW events received</p>
            <p className="text-xs opacity-60">
              {events.length === 0
                ? 'ETW session requires Administrator — run ARQENOR as admin'
                : `No events match provider "${filter}"`}
            </p>
          </div>
        ) : (
          <table className="w-full text-xs border-collapse">
            <thead className="sticky top-0 bg-surface z-10">
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-32">Provider</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-16">Event</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-16">PID</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-14">Level</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium">Description</th>
                <th className="text-right px-4 py-2.5 text-text-muted font-medium w-40">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((ev, idx) => {
                const isHighValue = HIGH_VALUE_EVENTS.has(ev.event_id)
                return (
                  <tr
                    key={`${ev.pid}-${ev.event_id}-${ev.timestamp}-${idx}`}
                    className={`data-row border-b border-border/50 hover:bg-surface-elevated/40 ${
                      isHighValue ? 'bg-high/5' : ''
                    }`}
                  >
                    {/* Provider badge */}
                    <td className="px-4 py-2">
                      <span className={`inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-medium ${providerColor(ev.provider_label)}`}>
                        {ev.provider_label}
                      </span>
                    </td>

                    {/* Event ID — highlight high-value */}
                    <td className="px-4 py-2 font-mono">
                      <span className={isHighValue ? 'text-high font-bold' : 'text-text-muted'}>
                        {ev.event_id}
                      </span>
                    </td>

                    {/* PID */}
                    <td className="px-4 py-2 font-mono text-text-muted">{ev.pid}</td>

                    {/* Level */}
                    <td className="px-4 py-2">
                      <span className="text-[10px] text-text-dim font-mono">
                        {levelLabel(ev.level)}
                      </span>
                    </td>

                    {/* Description */}
                    <td className="px-4 py-2 text-text max-w-xs">
                      <span className="block truncate" title={ev.description}>
                        {ev.description}
                      </span>
                      {ev.data_size > 0 && (
                        <span className="text-[10px] text-text-dim">
                          {ev.data_size}B payload
                        </span>
                      )}
                    </td>

                    {/* Timestamp */}
                    <td className="px-4 py-2 text-right font-mono text-[10px] text-text-dim">
                      {new Date(ev.timestamp).toLocaleString()}
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
