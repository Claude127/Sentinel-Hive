"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { Activity, Map, Brain, Settings, AlertCircle, Zap } from "lucide-react"

const navigation = [
  { name: "Overview", href: "/dashboard", icon: Activity },
  { name: "Real-time Attacks", href: "/dashboard/attacks", icon: AlertCircle },
  { name: "Geolocation", href: "/dashboard/geo", icon: Map },
  { name: "ML Classification", href: "/dashboard/ml", icon: Brain },
  { name: "Honeypots", href: "/dashboard/honeypots", icon: Zap },
  { name: "Settings", href: "/dashboard/settings", icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()

  return (
    <aside className="w-64 bg-sidebar border-r border-sidebar-border h-full">
      <div className="flex h-full flex-col">
        <div className="p-6 border-b border-sidebar-border">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-orange-500 rounded-lg flex items-center justify-center text-white font-bold">
              SH
            </div>
            <span className="text-lg font-bold text-sidebar-foreground">SentinelHive</span>
          </div>
        </div>

        <nav className="flex-1 space-y-2 p-4">
          {navigation.map((item) => {
            const Icon = item.icon
            const isActive = pathname === item.href
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 px-4 py-2 rounded-lg transition-colors",
                  isActive
                    ? "bg-sidebar-primary text-sidebar-primary-foreground"
                    : "text-sidebar-foreground hover:bg-sidebar-accent",
                )}
              >
                <Icon className="w-4 h-4" />
                <span className="text-sm font-medium">{item.name}</span>
              </Link>
            )
          })}
        </nav>

        <div className="p-4 border-t border-sidebar-border">
          <div className="text-xs text-sidebar-foreground/60 space-y-1">
            <p className="font-semibold">System Status</p>
            <p>All honeypots: Active</p>
            <p>ML Model: v1.0</p>
          </div>
        </div>
      </div>
    </aside>
  )
}
