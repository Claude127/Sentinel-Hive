"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

const classificationData = [
  { name: "Brute Force", value: 350, percentage: 38, fill: "#f97316" },
  { name: "Reconnaissance", value: 280, percentage: 30, fill: "#06b6d4" },
  { name: "Exploitation", value: 180, percentage: 20, fill: "#ef4444" },
  { name: "Malware", value: 100, percentage: 11, fill: "#a855f7" },
  { name: "Benign", value: 10, percentage: 1, fill: "#10b981" },
]

const mlMetrics = [
  { label: "Accuracy", value: "87.5%", color: "text-green-600" },
  { label: "Precision", value: "92.3%", color: "text-green-600" },
  { label: "Recall", value: "84.2%", color: "text-green-600" },
  { label: "F1-Score", value: "88.1%", color: "text-green-600" },
]

const confusionMatrix = [
  { actual: "BruteForce", predicted: "BruteForce", count: 245, accuracy: 70 },
  { actual: "BruteForce", predicted: "Recon", count: 35, accuracy: 10 },
  { actual: "Exploitation", predicted: "Exploitation", count: 162, accuracy: 90 },
  { actual: "Malware", predicted: "Malware", count: 89, accuracy: 89 },
]

export default function MLPage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold">ML Classification</h1>
        <p className="text-muted-foreground mt-2">Machine learning model predictions and metrics</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {mlMetrics.map((metric) => (
          <Card key={metric.label}>
            <CardContent className="pt-6">
              <div className="space-y-2">
                <p className="text-sm font-medium text-muted-foreground">{metric.label}</p>
                <p className={`text-3xl font-bold ${metric.color}`}>{metric.value}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Attack Classification</CardTitle>
            <CardDescription>ML Model Predictions</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={classificationData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {classificationData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-4 space-y-2">
              {classificationData.map((item) => (
                <div key={item.name} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.fill }} />
                    <span>{item.name}</span>
                  </div>
                  <span className="font-semibold">{item.percentage}%</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Model Information</CardTitle>
            <CardDescription>Current ML Pipeline</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-sm font-medium text-muted-foreground">Model Version</p>
              <Badge className="mt-1">v1.0.0</Badge>
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">Algorithm</p>
              <Badge variant="outline" className="mt-1">
                XGBoost + Random Forest
              </Badge>
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">Training Dataset</p>
              <Badge variant="outline" className="mt-1">
                10,500 samples
              </Badge>
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">Last Updated</p>
              <Badge variant="outline" className="mt-1">
                2025-01-10 15:32
              </Badge>
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">Inference Time</p>
              <Badge variant="outline" className="mt-1">
                &lt;100ms
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Classification Confidence</CardTitle>
          <CardDescription>Model confidence by attack type</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={classificationData}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
              <XAxis dataKey="name" stroke="var(--color-muted-foreground)" />
              <YAxis
                stroke="var(--color-muted-foreground)"
                label={{ value: "Confidence (%)", angle: -90, position: "insideLeft" }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--color-background)",
                  border: "1px solid var(--color-border)",
                }}
              />
              <Bar dataKey="percentage" fill="var(--color-chart-3)" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  )
}
