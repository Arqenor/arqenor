import { cn } from '@/lib/utils'
import { type ButtonHTMLAttributes, forwardRef } from 'react'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'accent' | 'ghost' | 'destructive' | 'outline'
  size?:    'sm' | 'md' | 'lg' | 'icon'
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'md', children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center gap-2 font-medium transition-all',
          'rounded focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent',
          'disabled:pointer-events-none disabled:opacity-40',
          // variants
          variant === 'accent'      && 'bg-accent text-bg hover:bg-accent-dim',
          variant === 'default'     && 'bg-surface-elevated text-text border border-border hover:border-border-bright hover:bg-surface',
          variant === 'ghost'       && 'text-text-muted hover:text-text hover:bg-surface-elevated',
          variant === 'destructive' && 'bg-critical/10 text-critical border border-critical/30 hover:bg-critical/20',
          variant === 'outline'     && 'border border-border text-text hover:bg-surface-elevated',
          // sizes
          size === 'sm'   && 'px-3 py-1.5 text-xs',
          size === 'md'   && 'px-4 py-2 text-sm',
          size === 'lg'   && 'px-6 py-2.5 text-sm',
          size === 'icon' && 'size-8 p-0',
          className,
        )}
        {...props}
      >
        {children}
      </button>
    )
  },
)
Button.displayName = 'Button'
