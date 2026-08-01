# Angular 22 & UI Specification

## Motivation
The frontend layer requires modernization from an outdated Angular 13 setup utilizing Material components, to a lightweight, performant, and reactive application running on Angular 22.

## Core Directives

### 1. Framework Fundamentals
- **Strict Standalone:** No `NgModule` configurations.
- **Signals:** Reactive state will be handled using Angular Signals (`signal`, `computed`, `effect`) replacing RxJS `BehaviorSubject` implementations.
- **Control Flow:** Component templates will exclusively use the built-in control flow (`@if`, `@for`, `@switch`) instead of structural directives (`*ngIf`, `*ngFor`).

### 2. Styling and Layout
- **Tailwind 4:** All styling will be handled via Tailwind CSS v4 in CSS-first mode, replacing SCSS files where possible.
- **Obsidian Theme:** The theme will embrace glassmorphic surfaces (`backdrop-filter`), slate dark mode palettes, and sleek micro-animations for interactions.
- **Lucide Icons:** Used in place of FontAwesome for a clean, tree-shakeable iconography layer.

### 3. Components and Third-Party Libs
- Angular Material is fully deprecated.
- **spartan/ui:** We will use the Spartan UI component library (Tailwind + Radix primitives) to implement the sleek, custom design components.
- **Code Editor:** The code-context viewer will embed **CodeMirror 6**, providing syntax highlighting for scanned source files.
- **Charts:** The dashboard will leverage upgraded `ngx-charts` alongside custom SVGs to represent security scores and project trends.

### 4. Code Organization
The `src/app` structure will follow a feature-based structure:
- `/core`: Layout components, platform abstractions, state stores.
- `/features/dashboard`: Aggregated metrics.
- `/features/projects`: Project CRUD, findings grids, detailed code views.
- `/features/settings`: AI configuration, Auth settings, Webhooks.
- `/shared/ui`: Reusable custom UI components (buttons, cards, badges, dialogs).
