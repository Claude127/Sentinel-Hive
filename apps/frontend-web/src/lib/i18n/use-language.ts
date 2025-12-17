"use client"

import { useEffect, useState } from "react"
import { useLanguageStore } from "@/stores/language-store"
import type { Language } from "./translations"

export function useLanguage() {
  const [mounted, setMounted] = useState(false)
  const { language, setLanguage } = useLanguageStore()

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return { language: "en" as Language, setLanguage }
  }

  return { language, setLanguage }
}
