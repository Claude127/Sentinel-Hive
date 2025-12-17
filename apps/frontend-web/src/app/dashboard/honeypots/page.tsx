"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Activity } from "lucide-react"

const honeypots = [
  {
    name: "SSH Honeypot",
    technology: "Cowrie",
    status: "online",
    uptime: "99.8%",
    attacks: 2547,
    lastAttack: "14:32:15",
    port: 2222,
    banner: "OpenSSH_7.4",
  },
  {
    name: "Web Honeypot",
    technology: "Dionaea",
    status: "online",
    uptime: "99.9%",
    attacks: 1284,
    lastAttack: "14:31:42",
    port: 8080,
    banner: "Apache/2.4.41",
  },
  {
    name: "IoT Honeypot",
    technology: "Conpot",
    status: "online",
    uptime: "98.7%",
    attacks: 456,
    lastAttack: "14:30:33",
    port: 502,
    banner: "SCADA ICS System",
  },
]

export default function HoneypotsPage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold">Honeypots Status</h1>
        <p className="text-muted-foreground mt-2">Real-time honeypot health and statistics</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {honeypots.map((hp) => (
          <Card key={hp.name}>
            <CardHeader>
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle className="text-lg">{hp.name}</CardTitle>
                  <CardDescription>{hp.technology}</CardDescription>
                </div>
                <Badge className={hp.status === "online" ? "bg-green-600" : "bg-red-600"}>{hp.status}</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Uptime</p>
                  <p className="text-2xl font-bold text-green-600">{hp.uptime}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Total Attacks</p>
                  <p className="text-2xl font-bold">{hp.attacks.toLocaleString()}</p>
                </div>
              </div>

              <div className="space-y-2 pt-2 border-t">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Port</span>
                  <code className="font-mono">{hp.port}</code>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Banner</span>
                  <code className="font-mono text-xs truncate">{hp.banner}</code>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Last Attack</span>
                  <code className="font-mono">{hp.lastAttack}</code>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2 border-t">
                <Activity className="w-4 h-4 text-green-600" />
                <span className="text-sm">Active and monitoring</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>System Health Indicators</CardTitle>
          <CardDescription>Overall infrastructure status</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">CPU Usage</span>
                <span className="text-sm font-bold">34%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div className="bg-blue-600 h-2 rounded-full" style={{ width: "34%" }} />
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Memory Usage</span>
                <span className="text-sm font-bold">52%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div className="bg-orange-600 h-2 rounded-full" style={{ width: "52%" }} />
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Disk Space</span>
                <span className="text-sm font-bold">28%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div className="bg-green-600 h-2 rounded-full" style={{ width: "28%" }} />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
