import { useEffect, useState, useCallback } from 'react'
import { Database, RefreshCw, Check, Download } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardValue } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { invoke } from '@tauri-apps/api/core'
import type { IocStats } from '@/lib/types'

const FEEDS = [
  { name: 'MalwareBazaar', desc: 'Malware hash repository' },
  { name: 'Feodo Tracker', desc: 'Botnet C2 indicators' },
  { name: 'URLhaus',       desc: 'Malicious URL database' },
  { name: 'ThreatFox',     desc: 'IOC sharing platform' },
]

const EMPTY_STATS: IocStats = {
  sha256_count: 0, md5_count: 0, ip_count: 0,
  domain_count: 0, url_count: 0, total: 0,
  last_updated: null,
}

export default function IocDatabase() {
  const [stats, setStats]             = useState<IocStats>(EMPTY_STATS)
  const [loading, setLoading]         = useState(true)
  const [refreshing, setRefreshing]   = useState(false)
  const [addedCount, setAddedCount]   = useState<number | null>(null)

  const fetchStats = useCallback(async () => {
    setLoading(true)
    try {
      const data = await invoke<IocStats>('get_ioc_stats')
      setStats(data)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStats()
    const interval = setInterval(fetchStats, 30_000)
    return () => clearInterval(interval)
  }, [fetchStats])

  const refreshFeeds = async () => {
    setRefreshing(true)
    setAddedCount(null)
    try {
      const count = await invoke<number>('refresh_ioc_feeds')
      setAddedCount(count)
      await fetchStats()
    } finally {
      setRefreshing(false)
    }
  }

  const isEmpty = stats.total === 0

  const statCards = [
    { label: 'SHA-256 Hashes', value: stats.sha256_count },
    { label: 'MD5 Hashes',     value: stats.md5_count },
    { label: 'IP Addresses',   value: stats.ip_count },
    { label: 'Domains',        value: stats.domain_count },
    { label: 'URLs',           value: stats.url_count },
    { label: 'Total IOCs',     value: stats.total },
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-3">
        <Database className="size-3.5 text-accent" strokeWidth={1.5} />
        <h1 className="text-xs font-bold tracking-widest text-accent text-glow-accent">THREAT INTELLIGENCE</h1>
        <div className="flex-1" />
        <Button variant="ghost" size="sm" onClick={fetchStats} disabled={loading}>
          <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {isEmpty && !loading ? (
          <div className="flex flex-col items-center justify-center h-64 gap-3 text-text-muted">
            <Database className="size-10 opacity-20" strokeWidth={1} />
            <p className="text-sm">No IOCs loaded</p>
            <p className="text-xs opacity-60">Click Refresh Feeds to download threat feeds from abuse.ch</p>
            <Button variant="ghost" size="sm" onClick={refreshFeeds} disabled={refreshing} className="mt-2">
              <Download className={`size-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh Feeds
            </Button>
          </div>
        ) : (
          <>
            {/* Stats grid */}
            <div className="grid grid-cols-3 gap-4">
              {statCards.map(({ label, value }) => (
                <Card key={label}>
                  <CardHeader>
                    <CardTitle>{label}</CardTitle>
                  </CardHeader>
                  <CardValue>{value.toLocaleString()}</CardValue>
                </Card>
              ))}
            </div>

            {/* Last updated */}
            {stats.last_updated && (
              <p className="text-[11px] text-text-muted">
                Last updated: {new Date(stats.last_updated).toLocaleString()}
              </p>
            )}

            {/* Refresh feeds */}
            <div className="flex items-center gap-3">
              <Button variant="ghost" size="sm" onClick={refreshFeeds} disabled={refreshing}>
                <Download className={`size-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh Feeds
              </Button>
              {addedCount !== null && (
                <span className="text-xs text-low flex items-center gap-1">
                  <Check className="size-3" />
                  Added {addedCount} new IOCs
                </span>
              )}
            </div>

            {/* Feed sources */}
            <div>
              <h2 className="text-xs font-semibold uppercase tracking-widest text-text-muted mb-3">Feed Sources</h2>
              <div className="space-y-1.5">
                {FEEDS.map(feed => (
                  <div key={feed.name} className="flex items-center gap-3 rounded p-2.5 bg-surface-elevated border border-border">
                    <Check className="size-3.5 text-low shrink-0" />
                    <span className="text-xs text-text font-medium">{feed.name}</span>
                    <span className="text-[10px] text-text-muted">{feed.desc}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
