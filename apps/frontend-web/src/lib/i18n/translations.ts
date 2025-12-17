export const translations = {
  en: {
    dashboard: "Dashboard",
    realTimeAttacks: "Real-time Attacks",
    geolocation: "Geolocation",
    mlClassification: "ML Classification",
    honeypots: "Honeypots",
    settings: "Settings",
    overview: "Overview",
    recentAlerts: "Recent Alerts",
    threatDetection: "Real-time threat detection and honeypot monitoring",
    totalAttacks: "Total Attacks",
    activeHoneypots: "Active Honeypots",
    threatsBlocked: "Threats Blocked",
    avgResponseTime: "Avg Response Time",
  },
  fr: {
    dashboard: "Tableau de bord",
    realTimeAttacks: "Attaques en temps réel",
    geolocation: "Géolocalisation",
    mlClassification: "Classification ML",
    honeypots: "Honeypots",
    settings: "Paramètres",
    overview: "Aperçu",
    recentAlerts: "Alertes récentes",
    threatDetection: "Détection de menaces en temps réel et surveillance des honeypots",
    totalAttacks: "Total des attaques",
    activeHoneypots: "Honeypots actifs",
    threatsBlocked: "Menaces bloquées",
    avgResponseTime: "Temps de réponse moyen",
  },
}

export type Language = keyof typeof translations
export type TranslationKey = keyof typeof translations.en
