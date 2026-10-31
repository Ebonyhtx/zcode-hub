# ZCode Hub

[简体中文](README.md) | **English**

[![CI](https://github.com/Ebonyhtx/zcode-hub/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Release](https://github.com/Ebonyhtx/zcode-hub/actions/workflows/release.yml/badge.svg)](../../actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)

**A Tauri 2 desktop tool for one-click switching between multiple ZCode accounts, with quota display, benefit detection and per-account device identity.**

Switches only the login identity — projects, sessions and settings stay untouched. Local-first: no telemetry, no remote storage; quota & benefit queries go straight to official endpoints.

> ⚠️ Unofficial tool, not affiliated with Z.ai / Zhipu (BigModel). Respect their terms of service; account risk is yours.

## Features

- **Multi-account switching** — one click, auto-preserved current login (no lost accounts), client auto-restart
- **Dual-provider OAuth** — built-in Z.AI / BigModel login flows with business-token exchange and normalized profiles
- **Per-account device identity** — each account gets its own deviceMid + arms_uid written into the client on switch
- **Quota display** — grouped by plan (base / limited-time), humanized numbers, expiry dates
- **Benefit detection** — official `billing/preview` endpoint; per-account, all-accounts or tray trigger; scheduled auto-check with system notifications (toggleable)
- **Encrypted snapshots** — AES-256-GCM whole-file encryption, random key sealed with Windows DPAPI (bound to current user + machine)
- **Password backups** — portable `.zhb` bundles (PBKDF2-HMAC-SHA256 120k + AES-256-GCM) for cross-machine migration
- **UX** — light/dark themes, custom titlebar, window geometry memory, autostart, bilingual UI (zh/en)

## Install

Grab `ZCode Hub_x.x.x_x64-setup.exe` from [Releases](../../releases). Windows 10/11 x64 only.

## Usage

| Scenario | Action |
|---|---|
| Add account | "Add account" → pick Z.AI / BigModel → finish official login in browser |
| Switch | "⇄ Switch to this" on a card; the client restarts automatically |
| Check benefits | Card 🔍 (single) / "Check all" / tray menu "Check benefits now" |
| Claim | When detected, "Claim" opens the ZCode client — claim manually there |
| Backup / migrate | "Backup / Import" → set password → export `.zhb` → import on another machine |
| To tray | Titlebar ✕ hides to tray; real exit = tray icon → Quit |

## Security model

See [SECURITY.md](SECURITY.md) for the full data-storage & encryption design. Highlights:

- All data lives in `%APPDATA%\Roaming\zcode-hub`; no telemetry, no remote storage
- Snapshots are AES-256-GCM encrypted with a random key sealed by DPAPI — copied files are undecryptable elsewhere
- All writes are atomic (temp + rename); account ids are whitelisted against path traversal
- Strict WebView CSP (`script-src 'self'`, no inline handlers — event delegation)
- Signed auto-updates (minisign pubkey embedded; updater rejects unsigned artifacts)

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the leak-guard hooks, tests and the release process. Architecture & design notes: [docs/DESIGN.md](docs/DESIGN.md).

```bash
cargo test                          # unit tests (src-tauri)
npx --yes @tauri-apps/cli build --bundles nsis
```

## License

[MIT](LICENSE)
