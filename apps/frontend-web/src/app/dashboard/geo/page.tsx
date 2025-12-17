"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
} from "recharts"

const geoData = [
  { country: "China", attacks: 342, lat: 35, lng: 105 },
  { country: "Russia", attacks: 289, lat: 61, lng: 105 },
  { country: "USA", attacks: 156, lat: 37, lng: -95 },
  { country: "Brazil", attacks: 123, lat: -14, lng: -51 },
  { country: "India", attacks: 98, lat: 20, lng: 78 },
  { country: "Japan", attacks: 87, lat: 36, lng: 138 },
]

const topCountries = geoData.sort((a, b) => b.attacks - a.attacks).slice(0, 5)

export default function GeoPage() {
  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold">Geolocation Intelligence</h1>
        <p className="text-muted-foreground mt-2">Geographic distribution of attacks</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Top Attacking Countries</CardTitle>
            <CardDescription>Number of attack attempts by country</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={350}>
              <BarChart data={topCountries}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                <XAxis dataKey="country" stroke="var(--color-muted-foreground)" />
                <YAxis stroke="var(--color-muted-foreground)" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "var(--color-background)",
                    border: "1px solid var(--color-border)",
                  }}
                />
                <Bar dataKey="attacks" fill="var(--color-chart-1)" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Global Overview</CardTitle>
            <CardDescription>Attack statistics</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground">Total Countries</p>
                <p className="text-3xl font-bold">{geoData.length}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total Attacks</p>
                <p className="text-3xl font-bold">{geoData.reduce((a, b) => a + b.attacks, 0)}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Most Active</p>
                <p className="text-lg font-semibold">{topCountries[0].country}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Geographic Heat Map</CardTitle>
          <CardDescription>Attack intensity by coordinates</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={400}>
            <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
              <XAxis
                dataKey="lng"
                type="number"
                stroke="var(--color-muted-foreground)"
                label={{ value: "Longitude", position: "bottom" }}
              />
              <YAxis
                dataKey="lat"
                type="number"
                stroke="var(--color-muted-foreground)"
                label={{ value: "Latitude", angle: -90, position: "insideLeft" }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--color-background)",
                  border: "1px solid var(--color-border)",
                }}
                cursor={{ strokeDasharray: "3 3" }}
              />
              <Scatter name="Attacks" data={geoData} fill="var(--color-chart-1)" />
            </ScatterChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  )
}
