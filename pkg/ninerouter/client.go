package ninerouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	if key != "" && !SecureEndpoint(baseURL) {
		return nil, errors.New("refusing insecure credential transport")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("invalid 9Router endpoint")
	}
	if model == "" {
		return nil, errors.New("9Router model is required; discover one through GET /v1/models")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	maxRetries = max(0, min(maxRetries, 5))
	return &Client{baseURL: baseURL, key: key, model: model, http: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, maxRetries: maxRetries, cache: map[string]string{}}, nil
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
				if len(c.cache) < 128 {
					c.cache[prompt] = text
				}
				c.mu.Unlock()
				return text, nil
			}
			detail := strings.TrimSpace(string(body))
			if len(detail) > 500 {
				detail = detail[:500]
			}
			last = fmt.Errorf("9Router HTTP %d: %s", resp.StatusCode, detail)
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusRequestTimeout {
				// Auth/validation errors will not succeed on retry.
				return "", last
			}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/health", nil)
	if err != nil {
		return err
	}
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

// SecureEndpoint reports whether credentials may be sent to baseURL: HTTPS
// anywhere, or plain HTTP only to a loopback host (the default local 9Router).
func SecureEndpoint(baseURL string) bool {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return false
	}
	if strings.EqualFold(u.Scheme, "https") {
		return true
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
