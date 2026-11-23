package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

const (
	// Standard JSON-RPC 2.0 & LSP error codes.
	ErrCodeParseError           = -32700
	ErrCodeInvalidRequest       = -32600
	ErrCodeMethodNotFound       = -32601
	ErrCodeInvalidParams        = -32602
	ErrCodeInternalError        = -32603
	ErrCodeServerNotInitialized = -32002
)

// RPCRequest represents an incoming JSON-RPC 2.0 request or notification.
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the message has no request ID.
func (r *RPCRequest) IsNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// RPCResponse represents an outgoing JSON-RPC 2.0 response.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// RPCNotification represents an outgoing server-initiated notification.
type RPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// readMessage reads a single Content-Length framed LSP JSON-RPC message.
func readMessage(r *bufio.Reader) ([]byte, error) {
	contentLength := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF && line == "" {
				return nil, io.EOF
			}
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			if contentLength < 0 {
				// Ignore stray blank lines before headers.
				continue
			}
			break
		}
		colon := strings.IndexByte(trimmed, ':')
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colon])
		val := strings.TrimSpace(trimmed[colon+1:])
		if strings.EqualFold(key, "Content-Length") {
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid Content-Length %q", val)
			}
			contentLength = n
		}
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// writeMessage writes a single Content-Length framed LSP JSON-RPC payload with
// mutual exclusion so concurrent document and workspace scans never interleave.
func writeMessage(w io.Writer, mu *sync.Mutex, payload []byte) error {
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload))
	mu.Lock()
	defer mu.Unlock()
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
