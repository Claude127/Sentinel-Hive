export interface Attack {
  id: string
  sourceIp: string
  targetHoneypot: "SSH" | "Web" | "IoT"
  attackType: string
  severity: "critical" | "high" | "medium" | "low"
  payload: string
  country: string
  timestamp: string
  classification: string
  confidence: number
}

export interface HoneypotStatus {
  id: string
  name: string
  technology: string
  port: number
  status: "online" | "offline"
  uptime: number
  totalAttacks: number
  lastAttack: string
}

export const mockAttacks: Attack[] = Array.from({ length: 50 }, (_, i) => ({
  id: `attack-${i}`,
  sourceIp: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
  targetHoneypot: ["SSH", "Web", "IoT"][Math.floor(Math.random() * 3)] as any,
  attackType: ["Brute Force", "SQLi", "XSS", "Port Scan", "Reconnaissance", "RCE"][Math.floor(Math.random() * 6)],
  severity: ["critical", "high", "medium", "low"][Math.floor(Math.random() * 4)] as any,
  payload: "Sample attack payload",
  country: ["CN", "RU", "US", "BR", "JP", "IN"][Math.floor(Math.random() * 6)],
  timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
  classification: ["Brute Force", "Reconnaissance", "Exploitation", "Malware", "Benign"][Math.floor(Math.random() * 5)],
  confidence: Math.random() * 100,
}))

export const mockHoneypots: HoneypotStatus[] = [
  {
    id: "hp-ssh",
    name: "SSH Honeypot",
    technology: "Cowrie",
    port: 2222,
    status: "online",
    uptime: 99.8,
    totalAttacks: 2547,
    lastAttack: "14:32:15",
  },
  {
    id: "hp-web",
    name: "Web Honeypot",
    technology: "Dionaea",
    port: 8080,
    status: "online",
    uptime: 99.9,
    totalAttacks: 1284,
    lastAttack: "14:31:42",
  },
  {
    id: "hp-iot",
    name: "IoT Honeypot",
    technology: "Conpot",
    port: 502,
    status: "online",
    uptime: 98.7,
    totalAttacks: 456,
    lastAttack: "14:30:33",
  },
]

export const dashboardStats = {
  totalAttacks: 4287,
  threatsBlocked: 98.7,
  avgResponseTime: 234,
  activeHoneypots: 3,
}
