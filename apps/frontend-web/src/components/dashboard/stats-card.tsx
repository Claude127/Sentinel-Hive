import { Card, CardContent } from "@/components/ui/card"
import type { LucideIcon } from "lucide-react"

interface StatsCardProps {
  icon: LucideIcon
  label: string
  value: string | number
  change?: string
  trend?: "up" | "down" | "stable"
}

export function StatsCard({ icon: Icon, label, value, change, trend }: StatsCardProps) {
  const trendColor = trend === "up" ? "text-green-600" : trend === "down" ? "text-red-600" : "text-blue-600"

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <p className="text-sm font-medium text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold">{value}</p>
            {change && <p className={`text-xs font-medium ${trendColor}`}>{change}</p>}
          </div>
          <Icon className="w-6 h-6 text-muted-foreground" />
        </div>
      </CardContent>
    </Card>
  )
}
