"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ComposedChart, Bar } from "recharts"
import { Search, RefreshCw, Download } from "lucide-react"

const realtimeData = [
  { time: "14:00", attacks: 12 },
  { time: "14:05", attacks: 18 },
  { time: "14:10", attacks: 25 },
  { time: "14:15", attacks: 20 },
  { time: "14:20", attacks: 32 },
  { time: "14:25", attacks: 28 },
  { time: "14:30", attacks: 35 },
]

const attacksLog = [
  { id: 1, time: "14:32:15", source: "152.89.43.2", target: "SSH", payload: "Hydra brute-force", severity: "critical" },
  {
    id: 2,
    time: "14:31:42",
    source: "45.33.12.98",
    target: "Web",
    payload: "SQLi: DROP TABLE users",
    severity: "high",
  },
  { id: 3, time: "14:31:08", source: "210.12.45.67", target: "SSH", payload: "Port scan Nmap", severity: "medium" },
  { id: 4, time: "14:30:33", source: "78.23.89.11", target: "IoT", payload: "Modbus request", severity: "low" },
  { id: 5, time: "14:29:51", source: "183.92.1.5", target: "Web", payload: "XSS payload", severity: "high" },
]

export default function AttacksPage() {
  const [searchTerm, setSearchTerm] = useState("")
  const [autoRefresh, setAutoRefresh] = useState(true)

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Real-time Attacks</h1>
          <p className="text-muted-foreground mt-2">Live attack feed from all honeypots</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant={autoRefresh ? "default" : "outline"}
            onClick={() => setAutoRefresh(!autoRefresh)}
            className="gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            {autoRefresh ? "Auto-refresh ON" : "Auto-refresh OFF"}
          </Button>
          <Button variant="outline" className="gap-2 bg-transparent">
            <Download className="w-4 h-4" />
            Export CSV
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Attack Activity (Last 30 minutes)</CardTitle>
          <CardDescription>Real-time detection stream</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <ComposedChart data={realtimeData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
              <XAxis dataKey="time" stroke="var(--color-muted-foreground)" />
              <YAxis stroke="var(--color-muted-foreground)" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--color-background)",
                  border: "1px solid var(--color-border)",
                }}
              />
              <Line type="monotone" dataKey="attacks" stroke="var(--color-chart-1)" strokeWidth={2} dot={false} />
              <Bar dataKey="attacks" fill="var(--color-chart-1)" fillOpacity={0.1} />
            </ComposedChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Attack Log</CardTitle>
              <CardDescription>Detailed event information</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Search className="w-4 h-4 absolute ml-3 text-muted-foreground" />
              <Input
                placeholder="Search by IP or target..."
                className="pl-9 w-48"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Payload Details</TableHead>
                  <TableHead>Severity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {attacksLog.map((attack) => (
                  <TableRow key={attack.id}>
                    <TableCell className="font-mono text-sm">{attack.time}</TableCell>
                    <TableCell className="font-mono">{attack.source}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{attack.target}</Badge>
                    </TableCell>
                    <TableCell className="text-sm truncate max-w-xs">{attack.payload}</TableCell>
                    <TableCell>
                      <Badge
                        className={
                          attack.severity === "critical"
                            ? "bg-red-100 text-red-800"
                            : attack.severity === "high"
                              ? "bg-orange-100 text-orange-800"
                              : attack.severity === "medium"
                                ? "bg-yellow-100 text-yellow-800"
                                : "bg-blue-100 text-blue-800"
                        }
                      >
                        {attack.severity}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
