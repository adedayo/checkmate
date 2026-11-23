package mcp

import (
	"sync"
	"time"
)

const (
	defaultSessionQueueSize  = 256
	defaultSessionIdleExpiry = 30 * time.Minute
	defaultSessionReapTick   = 1 * time.Minute
)

type mcpSession struct {
	id         string
	notifyCh   chan []byte
	done       chan struct{}
	closeOnce  sync.Once
	mu         sync.Mutex
	lastActive time.Time
}

func newMCPSession(id string) *mcpSession {
	return &mcpSession{
		id:         id,
		notifyCh:   make(chan []byte, defaultSessionQueueSize),
		done:       make(chan struct{}),
		lastActive: time.Now(),
	}
}

func (s *mcpSession) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *mcpSession) isIdle(now time.Time, expiry time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Sub(s.lastActive) >= expiry
}

func (s *mcpSession) enqueue(payload []byte) {
	s.touch()
	select {
	case <-s.done:
		return
	default:
	}
	// Non-blocking send so a slow SSE reader can never stall a scan.
	select {
	case s.notifyCh <- payload:
	default:
		// Drop the oldest queued notification to make room for the freshest progress update.
		select {
		case <-s.notifyCh:
		default:
		}
		select {
		case s.notifyCh <- payload:
		default:
		}
	}
}

func (s *mcpSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
	})
}

// sessionManager tracks active Streamable HTTP MCP sessions for SSE notification
// delivery and evicts idle sessions automatically.
type sessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*mcpSession
	idleTTL  time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
}

func newSessionManager() *sessionManager {
	sm := &sessionManager{
		sessions: make(map[string]*mcpSession),
		idleTTL:  defaultSessionIdleExpiry,
		stopCh:   make(chan struct{}),
	}
	go sm.reapLoop()
	return sm
}

func (sm *sessionManager) getOrCreate(id string) *mcpSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sess, ok := sm.sessions[id]; ok {
		sess.touch()
		return sess
	}
	sess := newMCPSession(id)
	sm.sessions[id] = sess
	return sess
}

func (sm *sessionManager) notify(id string, payload []byte) {
	if id == "" || len(payload) == 0 {
		return
	}
	sm.mu.RLock()
	sess := sm.sessions[id]
	sm.mu.RUnlock()
	if sess != nil {
		sess.enqueue(payload)
	}
}

func (sm *sessionManager) delete(id string) {
	sm.mu.Lock()
	sess, ok := sm.sessions[id]
	if ok {
		delete(sm.sessions, id)
	}
	sm.mu.Unlock()
	if ok && sess != nil {
		sess.close()
	}
}

func (sm *sessionManager) close() {
	sm.stopOnce.Do(func() {
		close(sm.stopCh)
	})
	sm.mu.Lock()
	all := make([]*mcpSession, 0, len(sm.sessions))
	for id, sess := range sm.sessions {
		all = append(all, sess)
		delete(sm.sessions, id)
	}
	sm.mu.Unlock()
	for _, sess := range all {
		sess.close()
	}
}

func (sm *sessionManager) reapLoop() {
	ticker := time.NewTicker(defaultSessionReapTick)
	defer ticker.Stop()
	for {
		select {
		case <-sm.stopCh:
			return
		case now := <-ticker.C:
			sm.reapExpired(now)
		}
	}
}

func (sm *sessionManager) reapExpired(now time.Time) {
	sm.mu.Lock()
	var expired []*mcpSession
	for id, sess := range sm.sessions {
		if sess.isIdle(now, sm.idleTTL) {
			expired = append(expired, sess)
			delete(sm.sessions, id)
		}
	}
	sm.mu.Unlock()
	for _, sess := range expired {
		sess.close()
	}
}
