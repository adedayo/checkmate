# Wails Runtime Specification

## Motivation
The legacy Electron desktop shell introduces massive bloat (Chromium + Node.js) and requires the CheckMate application to spawn its Go backend as a local HTTP server over a specific port. By transitioning to **Wails v2**, we can embed the Go codebase directly into the desktop binary, utilizing the lightweight OS-native webview.

## Architecture

```
┌───────────────────────────────────────────────┐
│              Wails Application                  │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │             Angular Frontend (v22)        │  │
│  │                                           │  │
│  │   Calls `window.go.main.App.Method(...)`  │  │
│  └───────────────────┬───────────────────────┘  │
│                      │ IPC (Native)             │
│  ┌───────────────────┴───────────────────────┐  │
│  │             Go Backend (App Struct)       │  │
│  │                                           │  │
│  │   Directly imports `pkg/api` & `pkg/sdk`  │  │
│  └───────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
```

## Implementation Details

### 1. Wails Initialization
The Wails application will be initialized in the `checkmate-app` directory. The Go application entrypoint (`main.go` for the desktop shell) will initialize a struct (e.g., `App`) that acts as the controller.

### 2. Go Exported Methods
The `App` struct will expose methods that map to the functionality previously served by the `/v1/` REST API.
For example, methods for CRUD operations on Projects, initiating scans, and managing AI Settings.

### 3. IPC vs HTTP & Dual Deployment Support
The application will support two deployment targets:
1. **Desktop Native (Wails)**
2. **Web / Docker (Browser)**

To achieve this, the Angular application will implement a **Data Provider Abstraction Layer**:
- An `AppConfig` or `PlatformService` will check for the existence of `window.go`.
- If `window.go` exists, it will use a `WailsDataProvider` that calls the Wails-generated TypeScript bindings (direct IPC, zero HTTP).
- If `window.go` is undefined (e.g. running in Docker), it will fall back to a `RestDataProvider` that uses Angular's `HttpClient` to communicate with the `checkmate api` HTTP server over `/v1/`.

### 4. Streaming
Progress updates (previously handled by Server-Sent Events or WebSockets) will be handled via Wails' native events system (`runtime.EventsEmit(ctx, "scan-progress", data)`). The Angular app will subscribe via `EventsOn`.
