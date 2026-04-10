import { useEffect, useState } from 'react'
import { NavLink } from 'react-router-dom'
import { invoke } from '@tauri-apps/api/core'
import { LayoutDashboard, Cpu, Network, DatabaseZap, Shield, ShieldAlert, Activity, Siren, Brain, Database } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Alert } from '@/lib/types'

const NAV = [
  { to: '/dashboard',   icon: LayoutDashboard, label: 'Dashboard'   },
  { to: '/alerts',      icon: ShieldAlert,     label: 'Alerts'      },
  { to: '/etw',         icon: Activity,        label: 'ETW Stream'  },
  { to: '/processes',   icon: Cpu,             label: 'Processes'   },
  { to: '/network',     icon: Network,         label: 'Network'     },
  { to: '/persistence', icon: DatabaseZap,     label: 'Persistence' },
  { to: '/incidents',   icon: Siren,           label: 'Incidents'   },
  { to: '/memory',      icon: Brain,           label: 'Memory'      },
  { to: '/ioc',         icon: Database,        label: 'Intel'       },
]

export default function Sidebar() {
  const [criticalCount, setCriticalCount] = useState(0)

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const data = await invoke<Alert[]>('get_alerts')
        setCriticalCount(data.filter(a => a.severity === 'Critical').length)
      } catch {
        // silently ignore — alerts may not be available yet
      }
    }

    fetchAlerts()
    const interval = setInterval(fetchAlerts, 30_000)
    return () => clearInterval(interval)
  }, [])

  return (
    <aside className="flex h-screen w-52 shrink-0 flex-col bg-sidebar border-r border-border">
      {/* Logo */}
      <div className="flex items-center gap-2.5 border-b border-border px-5 py-5">
        <Shield className="size-5 text-accent" strokeWidth={1.5} />
        <span className="text-sm font-bold tracking-[0.2em] text-text text-glow-accent">
          ARQENOR
        </span>
      </div>

      {/* Nav */}
      <nav className="flex flex-col gap-0.5 p-2 pt-4">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => cn(
              'flex items-center gap-3 rounded px-3 py-2.5 text-xs font-medium transition-all',
              isActive
                ? 'bg-accent/10 text-accent border border-accent/20'
                : 'text-text-muted hover:text-text hover:bg-surface-elevated border border-transparent',
            )}
          >
            <Icon className="size-4 shrink-0" strokeWidth={1.5} />
            {label}
            {to === '/alerts' && criticalCount > 0 && (
              <span className="ml-auto size-2 bg-critical rounded-full animate-pulse" />
            )}
          </NavLink>
        ))}
      </nav>

      {/* Bottom version */}
      <div className="mt-auto border-t border-border px-4 py-3">
        <p className="text-[10px] text-text-dim">v0.1.0 — open core</p>
      </div>
    </aside>
  )
}
