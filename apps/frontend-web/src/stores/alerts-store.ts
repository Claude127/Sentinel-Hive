import { create } from "zustand"
import { persist } from "zustand/middleware"

export interface Alert {
  id: string
  title: string
  severity: "critical" | "high" | "medium" | "low"
  timestamp: string
  read: boolean
}

interface AlertsStore {
  alerts: Alert[]
  addAlert: (alert: Alert) => void
  markAsRead: (id: string) => void
  clearAlerts: () => void
}

export const useAlertsStore = create<AlertsStore>()(
  persist(
    (set) => ({
      alerts: [],
      addAlert: (alert: Alert) =>
        set((state) => ({
          alerts: [alert, ...state.alerts].slice(0, 100),
        })),
      markAsRead: (id: string) =>
        set((state) => ({
          alerts: state.alerts.map((alert) => (alert.id === id ? { ...alert, read: true } : alert)),
        })),
      clearAlerts: () => set({ alerts: [] }),
    }),
    {
      name: "alerts-storage",
    },
  ),
)
