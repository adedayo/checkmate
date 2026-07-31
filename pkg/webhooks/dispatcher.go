package webhooks

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
)

// Dispatcher handles reliable webhook delivery
type Dispatcher struct {
	pm         store.PlatformStore
	httpClient *http.Client
}

// NewDispatcher creates a new webhook dispatcher
func NewDispatcher(pm store.PlatformStore) *Dispatcher {
	return &Dispatcher{
		pm: pm,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Dispatch queues an event for delivery to all subscribed webhooks.
func (d *Dispatcher) Dispatch(eventType string, data interface{}) {
	webhooks, err := d.pm.GetWebhooks()
	if err != nil || len(webhooks) == 0 {
		return
	}

	for _, wh := range webhooks {
		subscribed := false
		for _, e := range wh.Events {
			if e == eventType {
				subscribed = true
				break
			}
		}

		if subscribed {
			go d.DispatchToWebhook(wh, eventType, data)
		}
	}
}

// DispatchToWebhook delivers an event to a single specific webhook, with retries.
func (d *Dispatcher) DispatchToWebhook(wh *store.Webhook, eventType string, data interface{}) {
	payload := map[string]interface{}{
		"event":     eventType,
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      data,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal webhook payload: %v", err)
		return
	}

	mac := hmac.New(sha256.New, []byte(wh.Secret))
	mac.Write(payloadBytes)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	maxAttempts := 5
	baseBackoff := 2 * time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		startTime := time.Now()
		
		req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(payloadBytes))
		if err != nil {
			d.recordLog(wh.ID, eventType, attempt, nil, nil, err)
			break // malformed request, don't retry
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CheckMate-Signature", signature)

		resp, err := d.httpClient.Do(req)
		latency := int(time.Since(startTime).Milliseconds())

		if err != nil {
			d.recordLog(wh.ID, eventType, attempt, nil, &latency, err)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			
			d.recordLog(wh.ID, eventType, attempt, &resp.StatusCode, &latency, nil)

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// Success
				return
			}
		}

		if attempt < maxAttempts {
			time.Sleep(baseBackoff)
			baseBackoff *= 2 // exponential backoff
		}
	}
}

func (d *Dispatcher) recordLog(webhookID, eventType string, attempt int, statusCode, latency *int, err error) {
	logEntry := &store.WebhookDeliveryLog{
		ID:            "log_" + uuid.New().String()[:12],
		WebhookID:     webhookID,
		EventType:     eventType,
		AttemptNumber: attempt,
		ResponseCode:  statusCode,
		LatencyMs:     latency,
		CreatedAt:     time.Now(),
	}

	if err != nil {
		errMsg := err.Error()
		logEntry.ErrorMessage = &errMsg
	}

	_ = d.pm.RecordWebhookDelivery(logEntry)
}
