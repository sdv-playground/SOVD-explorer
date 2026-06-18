# SOVD Explorer Index

Tauri desktop GUI for browsing SOVD server state, diagnostics, firmware update flows, security helper, and OIDC login.

## Where to look

- `ARCHITECTURE.md` — authoritative module map, command list, state model, and known monolith shape.
- `package.json` — frontend scripts and dependencies.
- `src/App.tsx` — single-file React UI and state orchestration.
- `src-tauri/src/lib.rs` — Tauri command surface, SOVD client, helper and OIDC backend.
- `docs/standard-dids-and-security.md` — DID/security reference notes.
- `simulation/`, `scripts/` — helper data and setup scripts.

## Essential commands

No component-local `mise` file is present; use npm/Tauri from this submodule root.

```bash
npm install
npm run dev
npm run build
npm run lint
npm run tauri -- dev
npm run tauri -- build
./start.sh
```

Finding commands:

```bash
rg --files -g 'package.json' -g 'Cargo.toml' -g 'ARCHITECTURE.md' -g 'docs/**'
rg -n "invoke\(|tauri::command|security_helper|oidc|FlashClient|gateway|/updates" src src-tauri docs ARCHITECTURE.md
```

## Stack

- Tauri 2, Rust backend, React 18 + TypeScript + Vite frontend.
- `sovd-client`, `reqwest`, embedded axum callback server for OIDC.

## Guardrails

- Visual/UI changes must respect the existing dark diagnostic-console aesthetic.
- The app is currently monolithic: avoid scattering new state without first finding existing handlers in `App.tsx`/`lib.rs`.
- Gateway-aware routing and sub-entity path prefixes are central; do not flatten them.

## Gotchas

- `src/App.tsx` and `src-tauri/src/lib.rs` are large single-file modules; search before editing.
- Helper auth may be static or OIDC; stale JWT fallback is intentional.

## Missing docs/specs to watch

- No local `README.md` in this checkout; `ARCHITECTURE.md` is the primary project doc.
- Command/API contracts are documented in architecture, not generated from code.
