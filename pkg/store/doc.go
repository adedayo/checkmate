// Package store provides the SQLite-backed implementation of the CheckMate
// data store, replacing the previous Badger KV implementation.
//
// It implements the projects.ProjectManager interface from checkmate-core,
// meaning the rest of the codebase requires zero changes at the call sites —
// only the constructor in cmd/api.go changes.
//
// Schema is managed by versioned SQL migration files in migrations/ via
// golang-migrate. The connection uses WAL mode for concurrent read performance.
package store
