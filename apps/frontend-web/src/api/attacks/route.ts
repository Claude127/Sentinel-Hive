import { attacksAPI } from "@/api/client"

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url)
    const limit = Number.parseInt(searchParams.get("limit") || "50")
    const severity = searchParams.get("severity")
    const honeypot = searchParams.get("honeypot")

    let data = await attacksAPI.getRecent(limit)

    if (severity) {
      data = data.filter((a) => a.severity === severity)
    }

    if (honeypot) {
      data = data.filter((a) => a.targetHoneypot === honeypot)
    }

    return Response.json({
      success: true,
      data,
      count: data.length,
    })
  } catch (error) {
    return Response.json({ success: false, error: "Failed to fetch attacks" }, { status: 500 })
  }
}
