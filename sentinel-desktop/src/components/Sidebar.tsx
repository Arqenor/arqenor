import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Cpu, Network, DatabaseZap, Shield } from 'lucide-react'
import { cn } from '@/lib/utils'

const NAV = [
  { to: '/dashboard',   icon: LayoutDashboard, label: 'Dashboard'   },
  { to: '/processes',   icon: Cpu,             label: 'Processes'   },
  { to: '/network',     icon: Network,         label: 'Network'     },
  { to: '/persistence', icon: DatabaseZap,     label: 'Persistence' },
]

export default function Sidebar() {
  return (
    <aside className="flex h-screen w-52 shrink-0 flex-col bg-sidebar border-r border-border">
      {/* Logo */}
      <div className="flex items-center gap-2.5 border-b border-border px-5 py-5">
        <Shield className="size-5 text-accent" strokeWidth={1.5} />
        <span className="text-sm font-bold tracking-[0.2em] text-text text-glow-accent">
          SENTINEL
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
