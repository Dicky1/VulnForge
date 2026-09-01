package agent

import (
	"context"
	"errors"
	"github.com/example/sast-dast-analyzer/internal/models"
	"strings"
	"testing"
)

type validationStub string

func (s validationStub) ValidateFindings(context.Context, string) (string, error) {
	return string(s), nil
}

type validationFunc func(context.Context, string) (string, error)

func (f validationFunc) ValidateFindings(ctx context.Context, prompt string) (string, error) {
	return f(ctx, prompt)
}

func TestAIValidationAcceptsNumericAndStringBooleans(t *testing.T) {
	a := AIValidationAgent{Client: validationStub(`[{"finding_index":0,"is_valid":1.0,"confidence":"0.9","reason":"confirmed","exploitation_feasibility":"medium","zero_day_potential":"0.0"}]`), BatchSize: 10, MaxWorkers: 1, ConfidenceThreshold: .75}
	out, err := a.ValidateFindingsInBatch(context.Background(), []models.Finding{{ID: "one"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].AIConfidence != .9 || out[0].IsZeroDay {
		t.Fatalf("unexpected: %#v", out)
	}
}

func TestAIValidationTreatsNoneExplanationAsFalse(t *testing.T) {
	a := AIValidationAgent{Client: validationStub(`[{"finding_index":0,"is_valid":true,"confidence":0.8,"reason":"known issue","exploitation_feasibility":"low","zero_day_potential":"none. This is a known-pattern issue."}]`), BatchSize: 10, MaxWorkers: 1, ConfidenceThreshold: .75}
	out, err := a.ValidateFindingsInBatch(context.Background(), []models.Finding{{ID: "one"}})
	if err != nil || len(out) != 1 || out[0].IsZeroDay {
		t.Fatalf("unexpected: %#v, %v", out, err)
	}
}

func TestAIValidationFallsBackToOriginalOnBatchError(t *testing.T) {
	client := validationFunc(func(_ context.Context, prompt string) (string, error) {
		if strings.Contains(prompt, "fail-me") {
			return "", errors.New("boom: upstream unavailable")
		}
		return `[{"finding_index":0,"is_valid":true,"confidence":0.9,"reason":"confirmed","exploitation_feasibility":"low","zero_day_potential":false}]`, nil
	})
	a := AIValidationAgent{Client: client, BatchSize: 1, MaxWorkers: 1, ConfidenceThreshold: .75}
	in := []models.Finding{{ID: "bad", Title: "fail-me"}, {ID: "good", Title: "ok-one"}}
	out, err := a.ValidateFindingsInBatch(context.Background(), in)
	if err == nil {
		t.Fatal("expected the batch error to be surfaced to the caller")
	}
	if len(out) != 2 {
		t.Fatalf("expected the failed batch's finding to survive unvalidated instead of being dropped, got %#v", out)
	}
	var sawFallback bool
	for _, f := range out {
		if f.ID == "bad" {
			sawFallback = true
			if f.AIConfidence != 0 {
				t.Fatalf("fallback finding should keep its original (unvalidated) confidence, got %#v", f)
			}
		}
	}
	if !sawFallback {
		t.Fatal("expected finding \"bad\" from the failed batch to still be present")
	}
}
