package store

import (
	"sync"
)

// EventType categorises the event broadcast over SSE.
type EventType string

const (
	EventProgress EventType = "progress"
	EventFinding  EventType = "finding"
	EventComplete EventType = "complete"
)

// ScanEvent represents an event happening during a scan.
type ScanEvent struct {
	ScanID string
	Type   EventType
	Data   interface{}
}

// ScanEventBroker manages pub/sub subscriptions for scan events.
// It allows the API layer to subscribe to SSE streams for active scans.
type ScanEventBroker struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan ScanEvent]struct{}
}

// NewScanEventBroker creates a new event broker.
func NewScanEventBroker() *ScanEventBroker {
	return &ScanEventBroker{
		subscribers: make(map[string]map[chan ScanEvent]struct{}),
	}
}

// Subscribe adds a channel to receive events for a specific scan ID.
// It returns a cleanup function that MUST be called when the subscriber disconnects.
func (b *ScanEventBroker) Subscribe(scanID string) (<-chan ScanEvent, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan ScanEvent, 32)
	
	if b.subscribers[scanID] == nil {
		b.subscribers[scanID] = make(map[chan ScanEvent]struct{})
	}
	b.subscribers[scanID][ch] = struct{}{}

	cleanup := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		
		if subs, exists := b.subscribers[scanID]; exists {
			delete(subs, ch)
			close(ch)
			if len(subs) == 0 {
				delete(b.subscribers, scanID)
			}
		}
	}

	return ch, cleanup
}

// Publish broadcasts an event to all subscribers listening to the specific scan ID.
// If the subscriber channel is full, the event is dropped to prevent blocking the scanner.
func (b *ScanEventBroker) Publish(event ScanEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	subs, exists := b.subscribers[event.ScanID]
	if !exists {
		return
	}

	for ch := range subs {
		select {
		case ch <- event:
			// Sent successfully
		default:
			// Subscriber channel is full (e.g. slow client), drop event to avoid blocking DB/Scanner
		}
	}
}
