# OpenSpec Proposal: 002-app-modernisation

## Goal
Completely overhaul the CheckMate desktop application, migrating from a legacy Angular 13 + Electron architecture to a modern Angular 22 + Wails architecture.

## Motivation
The existing `checkmate-app` uses Electron, which is heavily bundled (Chromium + Node.js) and consumes significant system resources. Additionally, it relies on an outdated Angular 13 setup utilizing deprecated features (`NgModule`, `*ngIf`).

CheckMate's core backend is written in Go. By adopting **Wails v2**, we can compile the Go backend directly into the desktop application, leveraging the OS's native webview. This will:
1. Drastically reduce bundle size and memory footprint.
2. Eliminate the need for the desktop app to run a separate local HTTP server (`checkmate api`).
3. Allow direct, typed IPC communication between the Angular UI and the Go backend.

## Scope
1. **Scaffold a new Wails + Angular 22 project.**
2. **Implement a modern UI:** Migrate from Angular Material to a sleek, custom UI powered by **Tailwind 4**, utilizing modern Angular constructs (Standalone components, Signals, `@if`/`@for`).
3. **Refactor Code:** Transition `BehaviorSubject` logic to Angular Signals. Integrate CodeMirror 6 and up-to-date ngx-charts.
4. **Remove Legacy App:** Replace the existing `checkmate-app` directory entirely once the Wails application reaches feature parity.
