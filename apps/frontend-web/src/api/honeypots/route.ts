import { honeypotsAPI } from "@/api/client"

export async function GET() {
  try {
    const data = await honeypotsAPI.getAll()
    return Response.json({
      success: true,
      data,
      count: data.length,
    })
  } catch (error) {
    return Response.json({ success: false, error: "Failed to fetch honeypots" }, { status: 500 })
  }
}
