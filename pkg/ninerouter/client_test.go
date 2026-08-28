package ninerouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"[]"}}],"usage":{"prompt_tokens":4,"completion_tokens":1}}`))
	}))
	defer server.Close()
	c, err := NewClient(server.URL, "", "test/model", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.ValidateFindings(context.Background(), "validate")
	if err != nil || got != "[]" || c.TokenUsed() != 5 {
		t.Fatalf("got %q tokens=%d err=%v", got, c.TokenUsed(), err)
	}
}
