import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { AlertCircle, AlertTriangle, Zap } from "lucide-react"

const alerts = [
  {
    id: 1,
    title: "High SSH Brute Force",
    description: "152.89.43.2",
    severity: "critical",
    time: "2 mins ago",
  },
  {
    id: 2,
    title: "SQLi Detection",
    description: "Web Honeypot",
    severity: "high",
    time: "15 mins ago",
  },
  {
    id: 3,
    title: "New IP Reconnaissance",
    description: "210.12.45.67",
    severity: "medium",
    time: "1 hour ago",
  },
]

export function AlertsSummary() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Alerts</CardTitle>
        <CardDescription>Last 24 hours</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {alerts.map((alert) => (
            <div key={alert.id} className="flex items-start gap-3 p-3 rounded-lg bg-muted/50">
              {alert.severity === "critical" && <AlertCircle className="w-4 h-4 text-red-600 mt-0.5 flex-shrink-0" />}
              {alert.severity === "high" && <AlertTriangle className="w-4 h-4 text-orange-600 mt-0.5 flex-shrink-0" />}
              {alert.severity === "medium" && <Zap className="w-4 h-4 text-yellow-600 mt-0.5 flex-shrink-0" />}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{alert.title}</p>
                <p className="text-xs text-muted-foreground">{alert.description}</p>
                <p className="text-xs text-muted-foreground mt-1">{alert.time}</p>
              </div>
              <Badge variant="outline" className="flex-shrink-0">
                {alert.severity}
              </Badge>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
