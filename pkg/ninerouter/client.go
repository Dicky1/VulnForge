package ninerouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	baseURL, key, model string
	http                *http.Client
	maxRetries          int
	cache               map[string]string
	mu                  sync.RWMutex
	tokens              atomic.Int64
}
type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []message `json:"messages"`
	Temperature float64   `json:"temperature"`
	Stream      bool      `json:"stream"`
}
type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type chatResponse struct {
	Choices []struct {
		Message message `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func NewClient(baseURL, key, model string, timeout time.Duration, maxRetries int) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	baseURL = strings.TrimSuffix(baseURL, "/v1")
	if baseURL == "" {
		baseURL = "http://localhost:20128"
	}
	if model == "" {
		return nil, errors.New("9Router model is required; discover one through GET /v1/models")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	return &Client{baseURL: baseURL, key: key, model: model, http: &http.Client{Timeout: timeout}, maxRetries: maxRetries, cache: map[string]string{}}, nil
}
func (c *Client) ValidateFindings(ctx context.Context, prompt string) (string, error) {
	c.mu.RLock()
	cached, ok := c.cache[prompt]
	c.mu.RUnlock()
	if ok {
		return cached, nil
	}
	payload, _ := json.Marshal(chatRequest{Model: c.model, Messages: []message{{Role: "system", Content: "Return only the structured JSON requested by the user."}, {Role: "user", Content: prompt}}, Temperature: 0, Stream: false})
	var last error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		if c.key != "" {
			req.Header.Set("Authorization", "Bearer "+c.key)
		}
		resp, err := c.http.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if readErr != nil {
				return "", readErr
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var result chatResponse
				if err = json.Unmarshal(body, &result); err != nil {
					return "", fmt.Errorf("decode 9Router response: %w", err)
				}
				if len(result.Choices) == 0 || result.Choices[0].Message.Content == "" {
					return "", errors.New("9Router returned no assistant content")
				}
				text := result.Choices[0].Message.Content
				used := result.Usage.PromptTokens + result.Usage.CompletionTokens
				if used == 0 {
					used = (len(prompt) + len(text) + 3) / 4
				}
				c.tokens.Add(int64(used))
				c.mu.Lock()
				c.cache[prompt] = text
				c.mu.Unlock()
				return text, nil
			}
			last = fmt.Errorf("9Router HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		} else {
			last = err
		}
		if attempt < c.maxRetries {
			timer := time.NewTimer(time.Duration(1<<attempt) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			case <-timer.C:
			}
		}
	}
	return "", fmt.Errorf("9Router request failed after retries: %w", last)
}
func (c *Client) TokenUsed() int { return int(c.tokens.Load()) }
func (c *Client) Health(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/health", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("9Router health HTTP %d", resp.StatusCode)
	}
	return nil
}
