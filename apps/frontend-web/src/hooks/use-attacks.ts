"use client"

import { useState, useEffect } from "react"
import type { Attack } from "@/api/mock-data"
import { attacksAPI } from "@/api/client"

interface UseAttacksOptions {
  limit?: number
  autoRefresh?: boolean
  refreshInterval?: number
}

export function useAttacks(options: UseAttacksOptions = {}) {
  const { limit = 50, autoRefresh = true, refreshInterval = 5000 } = options
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    let isMounted = true

    const fetchAttacks = async () => {
      try {
        setLoading(true)
        const data = await attacksAPI.getRecent(limit)
        if (isMounted) {
          setAttacks(data)
          setError(null)
        }
      } catch (err) {
        if (isMounted) {
          setError(err instanceof Error ? err : new Error("Failed to fetch attacks"))
        }
      } finally {
        if (isMounted) {
          setLoading(false)
        }
      }
    }

    fetchAttacks()

    if (autoRefresh) {
      const interval = setInterval(fetchAttacks, refreshInterval)
      return () => clearInterval(interval)
    }

    return () => {
      isMounted = false
    }
  }, [limit, autoRefresh, refreshInterval])

  return { attacks, loading, error }
}
