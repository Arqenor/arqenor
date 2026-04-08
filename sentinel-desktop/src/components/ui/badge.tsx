import { cn } from '@/lib/utils'
import type { RiskLevel, HostRisk } from '@/lib/types'

type Risk = RiskLevel | HostRisk

const RISK_STYLES: Record<string, string> = {
  Critical: 'bg-critical/10 text-critical border-critical/40',
  High:     'bg-high/10    text-high    border-high/40',
  Medium:   'bg-medium/10  text-medium  border-medium/40',
  Low:      'bg-low/10     text-low     border-low/40',
  Normal:   'bg-normal/10  text-normal  border-normal/40',
}

interface RiskBadgeProps {
  risk:      Risk
  className?: string
}

export function RiskBadge({ risk, className }: RiskBadgeProps) {
  return (
    <span className={cn('risk-badge', RISK_STYLES[risk] ?? RISK_STYLES.Normal, className)}>
      {risk === 'Normal' ? '—' : risk}
    </span>
  )
}

interface BadgeProps {
  children:   React.ReactNode
  variant?:   'default' | 'outline' | 'accent'
  className?: string
}

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border',
      variant === 'accent'  && 'bg-accent/10 text-accent border-accent/30',
      variant === 'default' && 'bg-surface-elevated text-text-muted border-border',
      variant === 'outline' && 'bg-transparent text-text border-border',
      className,
    )}>
      {children}
    </span>
  )
}
