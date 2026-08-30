package agent

import (
	"context"
	"github.com/example/sast-dast-analyzer/internal/models"
	"testing"
)

type validationStub string

func (s validationStub) ValidateFindings(context.Context, string) (string, error) {
	return string(s), nil
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
