import { create } from "zustand"
import { persist } from "zustand/middleware"

interface DashboardPreferences {
  autoRefresh: boolean
  refreshInterval: number
  selectedHoneypots: string[]
  dateRange: "day" | "week" | "month"
}

interface DashboardStore {
  preferences: DashboardPreferences
  setAutoRefresh: (enabled: boolean) => void
  setRefreshInterval: (interval: number) => void
  setSelectedHoneypots: (honeypots: string[]) => void
  setDateRange: (range: "day" | "week" | "month") => void
}

export const useDashboardStore = create<DashboardStore>()(
  persist(
    (set) => ({
      preferences: {
        autoRefresh: true,
        refreshInterval: 30,
        selectedHoneypots: ["SSH", "Web", "IoT"],
        dateRange: "day",
      },
      setAutoRefresh: (enabled: boolean) =>
        set((state) => ({
          preferences: { ...state.preferences, autoRefresh: enabled },
        })),
      setRefreshInterval: (interval: number) =>
        set((state) => ({
          preferences: { ...state.preferences, refreshInterval: interval },
        })),
      setSelectedHoneypots: (honeypots: string[]) =>
        set((state) => ({
          preferences: { ...state.preferences, selectedHoneypots: honeypots },
        })),
      setDateRange: (range: "day" | "week" | "month") =>
        set((state) => ({
          preferences: { ...state.preferences, dateRange: range },
        })),
    }),
    {
      name: "dashboard-preferences",
    },
  ),
)
