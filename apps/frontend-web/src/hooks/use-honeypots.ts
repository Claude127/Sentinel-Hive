"use client"

import { useState, useEffect } from "react"
import type { HoneypotStatus } from "@/api/mock-data"
import { honeypotsAPI } from "@/api/client"

export function useHoneypots() {
  const [honeypots, setHoneypots] = useState<HoneypotStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    let isMounted = true

    const fetchHoneypots = async () => {
      try {
        setLoading(true)
        const data = await honeypotsAPI.getAll()
        if (isMounted) {
          setHoneypots(data)
          setError(null)
        }
      } catch (err) {
        if (isMounted) {
          setError(err instanceof Error ? err : new Error("Failed to fetch honeypots"))
        }
      } finally {
        if (isMounted) {
          setLoading(false)
        }
      }
    }

    fetchHoneypots()

    return () => {
      isMounted = false
    }
  }, [])

  return { honeypots, loading, error }
}
