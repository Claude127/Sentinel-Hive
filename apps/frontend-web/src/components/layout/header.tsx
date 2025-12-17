"use client"

import { useLanguage } from "@/lib/i18n/use-language"
import { Button } from "@/components/ui/button"
import { Bell, Settings, User } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

export function Header() {
  const { language, setLanguage } = useLanguage()

  return (
    <header className="border-b border-border bg-background/50 backdrop-blur-sm">
      <div className="flex items-center justify-between px-6 py-4">
        <div>
          <h2 className="text-sm text-muted-foreground">Welcome back to SentinelHive</h2>
        </div>

        <div className="flex items-center gap-4">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm">
                {language.toUpperCase()}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => setLanguage("en")}>English</DropdownMenuItem>
              <DropdownMenuItem onClick={() => setLanguage("fr")}>Français</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <Button variant="ghost" size="icon">
            <Bell className="w-4 h-4" />
          </Button>

          <Button variant="ghost" size="icon">
            <Settings className="w-4 h-4" />
          </Button>

          <Button variant="ghost" size="icon">
            <User className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </header>
  )
}
