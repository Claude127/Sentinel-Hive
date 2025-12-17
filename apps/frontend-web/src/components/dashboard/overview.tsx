"use client"

import type React from "react"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts"
import { AlertCircle, Activity, Shield, TrendingUp } from "lucide-react"

const attackTrendData = [
  { time: "00:00", attacks: 24 },
  { time: "04:00", attacks: 32 },
  { time: "08:00", attacks: 28 },
  { time: "12:00", attacks: 45 },
  { time: "16:00", attacks: 38 },
  { time: "20:00", attacks: 52 },
  { time: "24:00", attacks: 41 },
]

const attackTypeData = [
  { name: "Brute Force", value: 35, fill: "#f97316" },
  { name: "Reconnaissance", value: 25, fill: "#06b6d4" },
  { name: "Exploitation", value: 20, fill: "#ef4444" },
  { name: "Malware", value: 15, fill: "#a855f7" },
  { name: "Benign", value: 5, fill: "#10b981" },
]

const honeypotActivityData = [
  { name: "SSH", attempts: 156 },
  { name: "Web", attempts: 89 },
  { name: "IoT", attempts: 34 },
]

export function Overview() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard icon={AlertCircle} label="Total Attacks" value="2,547" change="+12.5%" trend="up" />
        <StatCard icon={Activity} label="Active Honeypots" value="3" change="All online" trend="stable" />
        <StatCard icon={Shield} label="Threats Blocked" value="98.7%" change="Detection Rate" trend="up" />
        <StatCard icon={TrendingUp} label="Avg Response Time" value="234ms" change="-5.2%" trend="down" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Attack Trends</CardTitle>
            <CardDescription>Last 24 hours</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={attackTrendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis dataKey="time" stroke="var(--color-muted-foreground)" />
                <YAxis stroke="var(--color-muted-foreground)" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "var(--color-background)",
                    border: "1px solid var(--color-border)",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="attacks"
                  fill="var(--color-chart-1)"
                  stroke="var(--color-chart-1)"
                  fillOpacity={0.2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Attack Types</CardTitle>
            <CardDescription>Distribution</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={attackTypeData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {attackTypeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Honeypot Activity</CardTitle>
          <CardDescription>Attempts per honeypot</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={honeypotActivityData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
              <XAxis dataKey="name" stroke="var(--color-muted-foreground)" />
              <YAxis stroke="var(--color-muted-foreground)" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--color-background)",
                  border: "1px solid var(--color-border)",
                }}
              />
              <Bar dataKey="attempts" fill="var(--color-chart-2)" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  )
}

interface StatCardProps {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: string
  change: string
  trend: "up" | "down" | "stable"
}

function StatCard({ icon: Icon, label, value, change, trend }: StatCardProps) {
  const trendColor = trend === "up" ? "text-green-600" : trend === "down" ? "text-red-600" : "text-blue-600"

  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <p className="text-sm font-medium text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold">{value}</p>
            <p className={`text-xs font-medium ${trendColor}`}>{change}</p>
          </div>
          <Icon className="w-6 h-6 text-muted-foreground" />
        </div>
      </CardContent>
    </Card>
  )
}
