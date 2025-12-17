"use client"

import { Overview } from "@/components/dashboard/overview"
import { AlertsSummary } from "@/components/dashboard/alerts-summary"
import { RecentAttacks } from "@/components/dashboard/recent-attacks"

export default function DashboardPage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground mt-2">Real-time threat detection and honeypot monitoring</p>
      </div>

      <Overview />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RecentAttacks />
        </div>
        <div>
          <AlertsSummary />
        </div>
      </div>
    </div>
  )
}
