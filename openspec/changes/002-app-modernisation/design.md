# OpenSpec Design: 002-app-modernisation

## Overview
The architecture will transition from Electron + Angular 13 to Wails v2 + Angular 22. This eliminates the need for an internal HTTP server for desktop users by compiling the Go backend directly into the desktop binary.

## 1. Desktop Runtime Layer (Wails)
- **Framework:** Wails v2.
- **Backend Language:** Go 1.24+.
- **Mechanism:** Wails uses the OS-native webview (WebView2 on Windows, WebKit on macOS, WebKitGTK on Linux). The CheckMate Go API will be embedded in the Wails app lifecycle (`OnStartup`, `OnShutdown`).
- **IPC:** Wails will automatically generate TypeScript bindings (`wailsjs/go/...`) for all exported Go methods, allowing the Angular UI to call the Go backend seamlessly without HTTP overhead.

## 2. Frontend Application (Angular 22)
- **Framework:** Angular v22, using the `@angular/build:application` (Vite) builder.
- **Paradigm:** 100% Standalone Components. No `NgModule`.
- **State Management:** Angular Signals will replace all `BehaviorSubject` implementations.
- **Control Flow:** Adopt `@if`, `@for`, and `@switch` syntax.
- **Injection:** Heavy use of the `inject()` function.

## 3. Design System & UI
- **CSS Framework:** Tailwind CSS v4, utilizing CSS-first configuration (`@theme`).
- **Aesthetics:** A "glassmorphic", dark-first design called "Obsidian", using deep slate backgrounds with purple/indigo accents.
- **Component Library:** Remove Angular Material. Replace with custom, Tailwind-native components or a lightweight headless library like `@angular/cdk`.
- **Icons:** Lucide icons, replacing FontAwesome.
- **Code Editor:** CodeMirror 6, dropping the CM5 wrappers.
- **Charts:** ngx-charts upgraded to latest, dropping `ngx-liquid-gauge` in favor of a custom SVG radial gauge.

## 4. Migration Execution
1. Rename the current `checkmate-app` directory to `checkmate-app-legacy`.
2. Run `wails init -n checkmate-app -t angular` (or create standard Angular project + Wails template).
3. Port core components piece-by-piece to the new directory, applying the new design system.
4. Replace all HTTP `CheckMateService` calls with the Wails-generated TypeScript bindings.
5. Validate all features (Scan streaming, Project CRUD, Exporting).
6. Delete `checkmate-app-legacy`.
