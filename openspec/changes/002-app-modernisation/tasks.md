# OpenSpec Tasks: 002-app-modernisation

## Phase 1: Wails & Angular Scaffolding
- `[x]` Rename `checkmate-app` to `checkmate-app-legacy`.
- `[x]` Initialize new Wails v2 project using the Angular template in `checkmate-app`.
- `[x]` Ensure the generated Angular project utilizes Angular v22 defaults (Standalone components).
- `[x]` Configure Tailwind CSS v4 in the Angular project.
- `[x]` Define the core "Obsidian" theme CSS custom properties.

## Phase 2: CheckMate Go Backend Integration
- `[/]` Modify Wails `main.go` and `app.go` to import and wrap the `checkmate` Go packages (`pkg/api`, `pkg/store`, `pkg/sdk`).
- `[/]` Export critical Go structs and methods to the frontend via the Wails `App` struct.
- [ ] Implement Wails Events to broadcast streaming progress data for scans.

## Phase 3: Core UI Framework
- `[x]` Implement global Sidebar and Layout components.
- `[/]` Implement reusable UI primitives (Buttons, Cards, Inputs, Tables) driven by Tailwind.
- [ ] Integrate Lucide icons.

## Phase 4: Feature Ports
- [ ] **Dashboard:** Build the score gauge and trend chart using latest ngx-charts/custom SVGs. Consume the Wails IPC bindings.
- [ ] **Project Management:** Port the "Create Project" flow.
- [ ] **Scanning Engine:** Integrate the CodeMirror 6 text editor for code contexts. Hook up the scanning progress bar via Wails Events.
- [ ] **Settings:** Port over git service setup, authentication logic, and webhooks config.

## Phase 5: Finalization
- `[x]` Delete `checkmate-app-legacy`. Directory removed; only OpenSpec
  references to the name remain, which are historical record rather than
  live dependencies.
- [ ] Merge OpenSpec specifications into `openspec/specs/` and archive `002-app-modernisation`.
