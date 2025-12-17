"use client"

import { useState, useEffect } from "react"
import { dashboardAPI } from "@/api/client"

export interface DashboardStats {
  totalAttacks: number
  threatsBlocked: number
  avgResponseTime: number
  activeHoneypots: number
}

export function useDashboardStats() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    let isMounted = true

    const fetchStats = async () => {
      try {
        setLoading(true)
        const data = await dashboardAPI.getStats()
        if (isMounted) {
          setStats(data)
          setError(null)
        }
      } catch (err) {
        if (isMounted) {
          setError(err instanceof Error ? err : new Error("Failed to fetch stats"))
        }
      } finally {
        if (isMounted) {
          setLoading(false)
        }
      }
    }

    fetchStats()

    return () => {
      isMounted = false
    }
  }, [])

  return { stats, loading, error }
}
