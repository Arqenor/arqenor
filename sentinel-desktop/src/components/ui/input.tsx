import { cn } from '@/lib/utils'
import { type InputHTMLAttributes, forwardRef } from 'react'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => {
    return (
      <input
        ref={ref}
        className={cn(
          'w-full rounded border border-border bg-surface-elevated px-3 py-1.5 text-sm text-text',
          'placeholder:text-text-muted',
          'focus:outline-none focus:border-accent/60 focus:bg-surface',
          'transition-colors',
          className,
        )}
        {...props}
      />
    )
  },
)
Input.displayName = 'Input'
