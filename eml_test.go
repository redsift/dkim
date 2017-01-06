package dkim

import (
	"bufio"
	"os"
	"testing"
)

func TestParseEml(t *testing.T) {
	samples := map[string]bool{
		"_test_data/valid_1.eml":   true,
		"_test_data/invalid_1.eml": false,
		"_test_data/pass01.eml":    true,
		"_test_data/pass02.eml":    true,
		"_test_data/pass03.eml":    true,
	}
	for sample, want := range samples {
		f, _ := os.Open(sample)
		m, err := ParseEml(bufio.NewReader(f))
		if err != nil {
			t.Errorf("%v: %v", sample, err)
			t.FailNow()
		}
		if got := m.Verify(); got != want {
			t.Errorf("%v got %v, want %v", sample, got, want)
		}
		f.Close()
	}
}
