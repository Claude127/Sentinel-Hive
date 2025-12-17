import Link from "next/link"
import { Button } from "@/components/ui/button"
import { ArrowRight } from "lucide-react"

export default function Home() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-800">
      <div className="text-center space-y-6">
        <h1 className="text-5xl font-bold text-white">SentinelHive</h1>
        <p className="text-xl text-slate-300 max-w-md">Intelligent Intrusion Detection System with Honeypots & ML</p>
        <Link href="/dashboard">
          <Button size="lg" className="gap-2">
            Launch Dashboard
            <ArrowRight className="w-4 h-4" />
          </Button>
        </Link>
      </div>
    </div>
  )
}
