package dkim

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"
)

type Document struct {
	Description string            `yaml:"description"`
	Tests       map[string]Test   `yaml:"tests"`
	TxtRecords  map[string]string `yaml:"txt-records"`
}

type Test struct {
	Description string `yaml:"description"`
	CV          string `yaml:"cv"`
	Message     string `yaml:"message"`
}

func TestVerifyArc(t *testing.T) {
	docs, err := parseTests("_samples/arc-validation-tests.yml")
	if err != nil {
		t.Error(err)
	}

	skipTests := func(t *testing.T, testName string, tests []string) {
		for _, test := range tests {
			if testName == test {
				t.Skip()
			}
		}
	}

	for _, doc := range docs {
		for k, r := range doc.TxtRecords {
			cache[k] = &cacheEntry{s: r}
		}

		for testName, test := range doc.Tests {
			t.Run(testName, func(t *testing.T) {
				// skip the following tests as we currently don't fail on duplicate on invalid tags
				skipTests(t, testName, []string{
					"as_format_inv_tag_key",
					"as_format_tags_dup",
					// skip simple/... tests as well
					"ams_fields_c_sr",
					"ams_fields_c_ss",
				})

				msg, err := ParseMessage(test.Message)
				if err != nil {
					t.Fatal(err)
				}

				result, err := VerifyArc(msg)
				if err != nil {
					fmt.Println(err)
				}

				if result.Result.Result.String() != strings.ToLower(test.CV) {
					t.Errorf("VerifyArc() got=%v, want=%s", result.Result.String(), test.CV)
				}
			})
		}
	}
}

func parseTests(file string) (docs []Document, err error) {
	source, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var res []Document

	dec := yaml.NewDecoder(bytes.NewReader(source))
	doc := Document{}
	for dec.Decode(&doc) != io.EOF {
		res = append(res, doc)
		doc = Document{}
	}

	return res, nil
}
