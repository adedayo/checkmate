package sdk

import (
	"context"
	"testing"
)

func TestNewScanner(t *testing.T) {
	opts := Options{
		ShowSource:       true,
		ExcludePatterns: []string{"node_modules"},
	}
	scanner := NewScanner(opts)
	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	if !scanner.opts.ShowSource {
		t.Errorf("Expected ShowSource to be true")
	}
	if len(scanner.opts.ExcludePatterns) != 1 {
		t.Errorf("Expected 1 exclude pattern, got %d", len(scanner.opts.ExcludePatterns))
	}
}

func TestScanStreamWithProgress(t *testing.T) {
	scanner := NewScanner(DefaultOptions())
	ch, _ := scanner.ScanStreamWithProgress(context.Background(), "/nonexistent/path/for/test")
	
	// Just ensure it doesn't panic and returns a channel that eventually closes
	count := 0
	for range ch {
		count++
	}
	
	if count > 10 {
		t.Errorf("Unexpectedly high number of events for a nonexistent path")
	}
}
