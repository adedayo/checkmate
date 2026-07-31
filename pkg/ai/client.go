package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/sdk"
	"github.com/adedayo/checkmate/pkg/store"
)

type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

type aiResponseJSON struct {
	FPLikelihood    float64  `json:"fpLikelihood"`
	Summary         string   `json:"summary"`
	RemediationHint *string  `json:"remediationHint"`
	ContextClues    []string `json:"contextClues"`
}

func TriageFinding(settings *store.AISettings, finding *sdk.Finding) (*sdk.AIAnnotation, error) {
	if !settings.Enabled {
		return nil, fmt.Errorf("AI triage is disabled")
	}

	mode := sdk.PromptMode(settings.DefaultPromptMode)
	if mode == "" {
		mode = sdk.PromptMode("REDACTED")
	}

	if mode == sdk.PromptMode("RAW_VALUE") {
		allowRaw := os.Getenv("CHECKMATE_AI_ALLOW_RAW_VALUE") == "true"
		if !allowRaw || !isLocalEndpoint(settings.BaseURL) {
			mode = sdk.PromptMode("REDACTED")
		}
	}

	reqBody := chatRequest{
		Model: settings.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUserPrompt(finding, mode)},
		},
		ResponseFormat: &responseFormat{Type: "json_object"},
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(settings.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if settings.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+settings.APIKey)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AI provider returned status: %d", resp.StatusCode)
	}

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, err
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices returned from AI provider")
	}

	content := chatResp.Choices[0].Message.Content
	
	// Sometimes Ollama adds markdown ```json blocks even when forcing json_object
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")

	var parsed aiResponseJSON
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse AI JSON response: %w. Raw content: %s", err, content)
	}

	var hint string
	if parsed.RemediationHint != nil {
		hint = *parsed.RemediationHint
	}

	ann := &sdk.AIAnnotation{
		Model:            settings.Model,
		Provider:         settings.Provider,
		PromptMode:       mode,
		FPLikelihood:     parsed.FPLikelihood,
		Summary:          parsed.Summary,
		RemediationHint:  hint,
		ContextClues:     parsed.ContextClues,
		GeneratedAt:      time.Now(),
		PromptTokens:     chatResp.Usage.PromptTokens,
		CompletionTokens: chatResp.Usage.CompletionTokens,
	}

	return ann, nil
}

func isLocalEndpoint(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	host := u.Hostname()

	if host == "localhost" || host == "host.docker.internal" || host == "ollama" {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
