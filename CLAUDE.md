# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The canonical repository guidelines live in AGENTS.md (product direction, layering, boundary contracts, MCP tool design, testing, commit rules). They apply in full:

@AGENTS.md

## Quick reference (supplements AGENTS.md)

- Toolchain: Node 24.18.0 / npm 11.16.0 (`.nvmrc`, `packageManager`). Most npm scripts first run `scripts/check-dependency-install.mjs`; rerun `npm ci` if it reports a stale install.
- Single test file: `npm run test:local -- tests/path/to/file.test.ts` (no build) or `npm run test:focused -- PATH...`. Plain `npx vitest run PATH` also works for unit-level projects.
- Vitest projects (`vitest.config.ts`): fast, no build needed — `domain`, `services`, `adapters`, `composition`, `conformance`, `evaluation` (`npm run test:fast`); require `npm run build:cached` first — `boundary`, `process-boundary`, `mcp-boundary`, `process-global`, `acceptance` (`npm run test:boundary`, `test:mcp`, `test:acceptance`). Select one with `npx vitest run --project <name>`.
- `npm run lint` is Oxlint plus `scripts/verify-module-boundaries.mjs`, which enforces the inward dependency direction described in AGENTS.md. A layering violation fails lint, not typecheck.
- Formatting: `npm run format` (Oxfmt). Dead code/exports: `npm run knip`.
- Changing a tool contract in `src/contracts/` or authored skill text in `skill-src/` requires `npm run build:cached` to regenerate the MCP tool catalog, skills, and product catalog (all gitignored; never commit them).
- Real-provider claims use the `verify:*` scripts (e.g. `verify:hopper`, `verify:ghidra`, `verify:ida`, `verify:browser`); see `docs/testing.md` for lanes and prerequisites.
- Run the CLI locally after building with `node scripts/rea.mjs <command>`; `npm start` launches the MCP server (`rea mcp`).
- Further design docs: `docs/architecture.mermaid`, `docs/tool-design.md`, `docs/mcp-contracts.md`, `docs/cli.md`, and per-capability guides under `docs/`.
