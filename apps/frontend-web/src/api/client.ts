import { type Attack, type HoneypotStatus, dashboardStats, mockAttacks, mockHoneypots } from "./mock-data"

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

export const attacksAPI = {
  async getRecent(limit = 50): Promise<Attack[]> {
    await delay(300)
    return mockAttacks.slice(0, limit).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  },

  async search(query: string): Promise<Attack[]> {
    await delay(200)
    return mockAttacks.filter(
      (a) => a.sourceIp.includes(query) || a.targetHoneypot.includes(query) || a.attackType.includes(query),
    )
  },

  async getByHoneypot(honeypot: string): Promise<Attack[]> {
    await delay(200)
    return mockAttacks.filter((a) => a.targetHoneypot === honeypot)
  },

  async getBySeverity(severity: string): Promise<Attack[]> {
    await delay(200)
    return mockAttacks.filter((a) => a.severity === severity)
  },
}

export const honeypotsAPI = {
  async getAll(): Promise<HoneypotStatus[]> {
    await delay(300)
    return mockHoneypots
  },

  async getById(id: string): Promise<HoneypotStatus | null> {
    await delay(200)
    return mockHoneypots.find((h) => h.id === id) || null
  },
}

export const dashboardAPI = {
  async getStats() {
    await delay(300)
    return dashboardStats
  },

  async getAttackTrends(hours = 24) {
    await delay(300)
    return Array.from({ length: hours }, (_, i) => ({
      time: `${i}:00`,
      attacks: Math.floor(Math.random() * 100),
    }))
  },

  async getAttacksByCountry() {
    await delay(300)
    return [
      { country: "China", attacks: 342 },
      { country: "Russia", attacks: 289 },
      { country: "USA", attacks: 156 },
      { country: "Brazil", attacks: 123 },
      { country: "India", attacks: 98 },
    ]
  },
}
