export function Footer() {
  return (
    <footer className="border-t border-border bg-background/50 px-6 py-4">
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <p>SentinelHive © 2025. All rights reserved.</p>
        <div className="flex items-center gap-4">
          <a href="#" className="hover:text-foreground transition-colors">
            Docs
          </a>
          <a href="#" className="hover:text-foreground transition-colors">
            Support
          </a>
        </div>
      </div>
    </footer>
  )
}
