import React, { useEffect, useRef, useState, useMemo } from 'react'

interface ScrollRevealProps {
  children: React.ReactNode
  className?: string
  delay?: number // in ms (e.g. 50, 100, 150)
  direction?: 'up' | 'down' | 'left' | 'right' | 'none'
  threshold?: number
}

export function ScrollReveal({
  children,
  className = '',
  delay = 0,
  direction = 'up',
  threshold = 0.08
}: ScrollRevealProps) {
  const [isVisible, setIsVisible] = useState(false)
  const domRef = useRef<HTMLDivElement>(null)

  const prefersReducedMotion = useMemo(() => {
    if (typeof window === 'undefined') return false
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  }, [])

  useEffect(() => {
    if (prefersReducedMotion) {
      setIsVisible(true)
      return
    }

    const currentEl = domRef.current
    if (!currentEl) return

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setIsVisible(true)
            observer.unobserve(entry.target)
          }
        })
      },
      {
        threshold,
        rootMargin: '0px 0px -40px 0px'
      }
    )

    observer.observe(currentEl)

    return () => {
      observer.disconnect()
    }
  }, [threshold, prefersReducedMotion])

  const getTransformClasses = () => {
    if (prefersReducedMotion || isVisible) return 'opacity-100 translate-x-0 translate-y-0'

    switch (direction) {
      case 'up':
        return 'opacity-0 translate-y-4'
      case 'down':
        return 'opacity-0 -translate-y-4'
      case 'left':
        return 'opacity-0 translate-x-4'
      case 'right':
        return 'opacity-0 -translate-x-4'
      case 'none':
        return 'opacity-0'
      default:
        return 'opacity-0 translate-y-4'
    }
  }

  return (
    <div
      ref={domRef}
      style={{
        transitionDelay: `${delay}ms`,
        transitionDuration: '380ms',
        transitionTimingFunction: 'cubic-bezier(0.16, 1, 0.3, 1)'
      }}
      className={`transition-all ${getTransformClasses()} ${className}`}
    >
      {children}
    </div>
  )
}
