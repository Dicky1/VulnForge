package claude

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

type Client struct {
	sdk        anthropic.Client
	model      string
	timeout    time.Duration
	maxRetries int
	cache      map[string]string
	mu         sync.RWMutex
	tokens     atomic.Int64
}

func NewClient(apiKey, model string, timeout time.Duration, maxRetries int) (*Client, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("ANTHROPIC_API_KEY is not set")
	}
	if model == "" {
		model = "claude-opus-4-8"
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	sdk := anthropic.NewClient(option.WithAPIKey(apiKey), option.WithMaxRetries(0))
	return &Client{sdk: sdk, model: model, timeout: timeout, maxRetries: maxRetries, cache: map[string]string{}}, nil
}
func (c *Client) ValidateFindings(ctx context.Context, prompt string) (string, error) {
	c.mu.RLock()
	v, ok := c.cache[prompt]
	c.mu.RUnlock()
	if ok {
		return v, nil
	}
	var last error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, c.timeout)
		msg, err := c.sdk.Messages.New(callCtx, anthropic.MessageNewParams{Model: anthropic.Model(c.model), MaxTokens: 2048, Messages: []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(prompt))}})
		cancel()
		if err == nil {
			var b strings.Builder
			for _, block := range msg.Content {
				if block.Type == "text" {
					b.WriteString(block.Text)
				}
			}
			v = b.String()
			if v == "" {
				return "", errors.New("Claude returned no text")
			}
			c.tokens.Add(int64((len(prompt) + len(v) + 3) / 4))
			c.mu.Lock()
			c.cache[prompt] = v
			c.mu.Unlock()
			return v, nil
		}
		last = err
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
	return "", fmt.Errorf("Claude request failed after retries: %w", last)
}
func (c *Client) TokenUsed() int { return int(c.tokens.Load()) }
