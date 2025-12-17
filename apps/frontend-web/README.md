# SentinelHive Dashboard - Week 1 Frontend

## Project Structure

### Pages

- `/` - Homepage with project introduction
- `/dashboard` - Main dashboard with overview, statistics, and charts
- `/dashboard/attacks` - Real-time attack feed with auto-refresh
- `/dashboard/geo` - Geolocation intelligence and attack distribution
- `/dashboard/ml` - Machine learning model metrics and classifications
- `/dashboard/honeypots` - Honeypot status and health indicators
- `/dashboard/settings` - Configuration and alert settings

### Technology Stack

- **Next.js 16** - React framework with App Router
- **TailwindCSS** - Utility-first CSS framework
- **Shadcn/ui** - High-quality React components
- **Recharts** - Composable charting library
- **Zustand** - State management with persistence
- **Formik + Yup** - Form management and validation
- **Lucide React** - Icon library
- **i18n** - Internationalization support (EN/FR)

### Key Features

✓ Real-time attack monitoring
✓ Auto-refreshing data with configurable intervals
✓ Multi-language support (English/French)
✓ Persistent user preferences with Zustand
✓ Form validation with Formik/Yup
✓ Mock API with realistic data
✓ Responsive design (mobile/tablet/desktop)
✓ Professional tech/security aesthetic

### Setup & Development

```bash
npm install
npm run dev
```

### API Endpoints (Mock)

- `GET /api/attacks` - Get attack list
- `GET /api/honeypots` - Get honeypot status
- `GET /api/dashboard/stats` - Get dashboard statistics

### Zustand Stores

- `useLanguageStore` - Language preference
- `useAlertsStore` - Alert notifications
- `useDashboardStore` - Dashboard preferences

### Environment

The project uses mock data for Week 1. Real API integration will be done in Weeks 2-3.
