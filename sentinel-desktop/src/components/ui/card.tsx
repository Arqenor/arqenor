import { cn } from '@/lib/utils'

interface CardProps {
  children:   React.ReactNode
  className?: string
  glow?:      boolean
}

export function Card({ children, className, glow }: CardProps) {
  return (
    <div className={cn(
      'rounded-lg border border-border bg-surface p-4',
      glow && 'border-accent/20 shadow-[0_0_20px_rgba(0,212,255,0.06)]',
      className,
    )}>
      {children}
    </div>
  )
}

export function CardHeader({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn('mb-3 flex items-center justify-between', className)}>{children}</div>
}

export function CardTitle({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <h3 className={cn('text-xs font-semibold uppercase tracking-widest text-text-muted', className)}>
      {children}
    </h3>
  )
}

export function CardValue({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('text-3xl font-bold text-text tracking-tight', className)}>
      {children}
    </div>
  )
}
