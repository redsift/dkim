package dkim

import (
	"bufio"
	"os"
	"testing"
)

func TestParseEml(t *testing.T) {
	{
		f, _ := os.Open("_test_data/valid_1.eml")
		defer f.Close()
		m, err := ParseEml(bufio.NewReader(f))
		if err != nil {
			t.Fail()
		}
		if m.Verify() != true {
			t.Fail()
		}
	}
	{
		f, _ := os.Open("_test_data/invalid_1.eml")
		defer f.Close()
		m, err := ParseEml(bufio.NewReader(f))
		if err != nil {
			t.Fail()
		}
		if m.Verify() == true {
			t.Fail()
		}
	}
}
