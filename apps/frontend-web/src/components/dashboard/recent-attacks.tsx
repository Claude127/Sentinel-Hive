"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"

const attacks = [
  {
    id: 1,
    sourceIp: "152.89.43.2",
    honeypot: "SSH",
    attackType: "Brute Force",
    severity: "critical",
    timestamp: "2025-01-12 14:23:45",
    country: "CN",
  },
  {
    id: 2,
    sourceIp: "45.33.12.98",
    honeypot: "Web",
    attackType: "SQLi",
    severity: "high",
    timestamp: "2025-01-12 14:15:22",
    country: "RU",
  },
  {
    id: 3,
    sourceIp: "210.12.45.67",
    honeypot: "SSH",
    attackType: "Reconnaissance",
    severity: "medium",
    timestamp: "2025-01-12 14:08:10",
    country: "JP",
  },
  {
    id: 4,
    sourceIp: "78.23.89.11",
    honeypot: "IoT",
    attackType: "Port Scan",
    severity: "low",
    timestamp: "2025-01-12 13:56:03",
    country: "BR",
  },
  {
    id: 5,
    sourceIp: "183.92.1.5",
    honeypot: "Web",
    attackType: "XSS Attempt",
    severity: "medium",
    timestamp: "2025-01-12 13:42:15",
    country: "KR",
  },
]

const severityColors = {
  critical: "bg-red-100 text-red-800 border-red-300",
  high: "bg-orange-100 text-orange-800 border-orange-300",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-300",
  low: "bg-blue-100 text-blue-800 border-blue-300",
}

export function RecentAttacks() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Attacks</CardTitle>
        <CardDescription>Real-time threat feed from honeypots</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source IP</TableHead>
                <TableHead>Honeypot</TableHead>
                <TableHead>Attack Type</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Country</TableHead>
                <TableHead>Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {attacks.map((attack) => (
                <TableRow key={attack.id}>
                  <TableCell className="font-mono text-sm">{attack.sourceIp}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{attack.honeypot}</Badge>
                  </TableCell>
                  <TableCell className="text-sm">{attack.attackType}</TableCell>
                  <TableCell>
                    <Badge className={`${severityColors[attack.severity as keyof typeof severityColors]} border`}>
                      {attack.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-center">{attack.country}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{attack.timestamp}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}
