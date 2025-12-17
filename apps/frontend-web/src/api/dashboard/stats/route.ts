import { dashboardAPI } from "@/api/client"

export async function GET() {
  try {
    const stats = await dashboardAPI.getStats()
    const trends = await dashboardAPI.getAttackTrends(24)
    const countries = await dashboardAPI.getAttacksByCountry()

    return Response.json({
      success: true,
      data: {
        stats,
        trends,
        countries,
      },
    })
  } catch (error) {
    return Response.json({ success: false, error: "Failed to fetch dashboard stats" }, { status: 500 })
  }
}
