# MACan

## Register
product

## Platform
web

## Users
Administrators and security teams managing UniFi WiFi deployments. They need a lightweight web panel to manage MAC authentication rules, SSID activation, controllers, approvals, online sessions, audit logs, and notifications without dealing with RADIUS config complexity.

## Product Purpose
MACan provides a clean web interface for MAC-based authentication rules on FreeRADIUS + UniFi. It tracks accept/reject decisions, automates SSID activation, maintenance mode, inactive sweeps, and CSV import/export while keeping everything auditable.

## Positioning
The single strategic claim: "MAC authentication rules per SSID. Fail-closed by default. Zero config for RADIUS."

## Brand Personality
Minimalist, secure, no-nonsense. 3-word: precise, reliable, calm.

## Anti-references
- Heavy RADIUS config files
- Unaudited MAC lists
- Overly complex dashboards
- SaaS credential bloat
- Dark-only gimmicks

## Design Principles
- Everything must be readable in 30 seconds
- Accept/reject decisions must be instantly scannable
- Security controls never buried in menus
- Mobile-first responsive layout
- Consistent dark/light mode with no preference bias

## Design Principles
- Clean, readable data tables with sticky headers
- Stat cards that feel interactive but lightweight
- Minimal sidebar with clear hierarchy
- Quick approval actions with confirmation
- Consistent spacing and radius for trust
- No unnecessary animations or motion unless clarifying
- Fail-closed mindset visible in every default state
- Audit trails visible in UI and logs

## Accessibility & Inclusion
WCAG AA. Keyboard navigation. High contrast per design tokens. Reduced motion support. Screen reader friendly tables and forms.

## Accessibility & Inclusion
WCAG AA. Keyboard navigation. High contrast tokens. Reduced motion support. Screen reader friendly tables and forms.

## Next steps
Style direction: Swiss Modernism 2.0 — diterapkan di `web/public/app.css` + `dashboard.ejs` (2026-08-05). Single accent, hairline, type-as-hierarchy, Inter. Selanjutnya: terapkan prinsip yang sama ke halaman lain (rules, approvals, sessions, logs, audit, settings) — tabel jadi tulang punggung, filter rail sticky, hairline divider, radius 2px.