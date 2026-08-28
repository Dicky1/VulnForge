package scorer

import "testing"

func TestCVSS31KnownVectors(t *testing.T) {
	c := &CVSSCalculator{}
	tests := []struct {
		m    CVSSMetrics
		want float64
	}{{CVSSMetrics{"N", "L", "N", "N", "U", "H", "H", "H"}, 9.8}, {CVSSMetrics{"L", "H", "L", "R", "U", "L", "L", "N"}, 3.3}}
	for _, tt := range tests {
		if got := c.CalculateScore(tt.m); got != tt.want {
			t.Fatalf("got %.1f want %.1f", got, tt.want)
		}
	}
}
