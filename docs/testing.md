# CheckMate Testing Standards

As part of our commitment to high quality and preventing regressions, CheckMate follows a Test-Driven Development (TDD) workflow. This document outlines our testing standards, preferred libraries, and best practices.

## Core Principles

1. **Test-Driven Development**: Write tests before, or immediately alongside, your code. 
2. **Cover Existing Code**: Ensure all existing capabilities (such as data store logic, config parsing, API endpoints) have adequate test coverage before adding new features.
3. **Deterministic & Fast**: Tests should be fast and deterministic. Use in-memory SQLite for data store tests, and avoid external dependencies (e.g., Docker) where possible for unit and integration testing.
4. **Isolated**: Tests must not rely on the execution order or shared state. Each test should set up and tear down its own requirements.

## Libraries

- **`testing`**: The Go standard library.
- **`github.com/stretchr/testify/require`**: Use this for assertions. `require` immediately fails the test on a failure, preventing confusing subsequent errors caused by the initial failure (unlike `assert` which continues execution).
- **`github.com/stretchr/testify/assert`**: Use this for assertions where you want multiple failures to be reported in a single test run (e.g., asserting on multiple independent fields of a struct).

## Types of Tests

### Unit Tests
- Fast, isolated tests focusing on a single function or struct.
- Prefer `t.Parallel()` for unit tests to ensure fast execution.

### Integration Tests (Data Layer)
- Since we use `modernc.org/sqlite` (pure Go), data layer tests should run against an in-memory database:
  `New("file::memory:?cache=shared")`
- This allows full integration testing of schema migrations, `db.go`, and data models without any external setup or file I/O latency.

## Running Tests

To run all tests locally:
```bash
go test -v ./...
```

To run with coverage:
```bash
go test -cover -v ./...
```
