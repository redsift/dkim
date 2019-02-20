package dkim

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCommonHeaders(t *testing.T) {
	for h := range commonHeader {
		if h != CanonicalMIMEHeaderKey(h) {
			t.Errorf("Non-canonical header %q in commonHeader", h)
		}
	}
	b := []byte("content-Length")
	want := "Content-Length"
	n := testing.AllocsPerRun(200, func() {
		if x := canonicalMIMEHeaderKey(b); x != want {
			t.Fatalf("canonicalMIMEHeaderKey(%q) = %q; want %q", b, x, want)
		}
	})
	if n > 0 {
		t.Errorf("canonicalMIMEHeaderKey allocs = %v; want 0", n)
	}
}

func reader(s string) *Reader {
	return NewReader(bufio.NewReader(strings.NewReader(s)))
}

func TestReader_ReadContinuedLineSlice(t *testing.T) {
	r := reader("line1\nline\n 2\nline\t\n\t3\nline 4 \n")
	read := func() (string, string, error) {
		f, u, err := r.readContinuedLineSlice()
		return string(f), string(u), err
	}
	f, u, err := read()
	if f != "line1" || u != "line1" || err != nil {
		t.Fatalf("Line 1: %q, %q, %v", f, u, err)
	}
	f, u, err = read()
	if f != "line 2" || u != "line\n 2" || err != nil {
		t.Fatalf("Line 2: %q, %q, %v", f, u, err)
	}
	f, u, err = read()
	if f != "line 3" || u != "line\t\n\t3" || err != nil {
		t.Fatalf("Line 3: %q, %q, %v", f, u, err)
	}
	f, u, err = read()
	if f != "line 4" || u != "line 4 " || err != nil {
		t.Fatalf("Line 4: %q, %q, %v", f, u, err)
	}
	f, u, err = read()
	if f != "" || u != "" || err != io.EOF {
		t.Fatalf("EOF: %q, %q, %v", f, u, err)
	}
}

func TestReadMIMEHeader(t *testing.T) {
	r := reader("my-key: Value 1  \r\nLong-key: Even \n Longer Value\r\nmy-Key: Value 2\r\n\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{
		"My-Key": {
			{"my-key", " Value 1  ", "Value 1"},
			{"my-Key", " Value 2", "Value 2"},
		},
		"Long-Key": {
			{"Long-key", " Even \n Longer Value", "Even Longer Value"},
		},
	}
	if err != nil {
		t.Errorf("ReadMIMEHeader() err=%v, want=nil", err)
	}
	if diff := cmp.Diff(want, m); diff != "" {
		t.Errorf("ReadMIMEHeader() results differs: (-want +got)\n%s", diff)
	}
}

func TestReadMIMEHeader_single(t *testing.T) {
	r := reader("Foo: bar \n\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{"Foo": {{"Foo", " bar ", "bar"}}}
	if err != nil {
		t.Errorf("ReadMIMEHeader() err=%v, want=nil", err)
	}
	if diff := cmp.Diff(want, m); diff != "" {
		t.Errorf("ReadMIMEHeader() results differs: (-want +got)\n%s", diff)
	}
}

func TestReadMIMEHeader_noKey(t *testing.T) {
	r := reader(": bar\ntest-1: 1\n\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{"Test-1": {{"test-1", " 1", "1"}}}
	if err != nil {
		t.Errorf("ReadMIMEHeader() err=%v, want=nil", err)
	}
	if diff := cmp.Diff(want, m); diff != "" {
		t.Errorf("ReadMIMEHeader() results differs: (-want +got)\n%s", diff)
	}
}

func TestReadMIMEHeader_large(t *testing.T) {
	data := make([]byte, 16*1024)
	for i := 0; i < len(data); i++ {
		data[i] = 'x'
	}
	sdata := string(data)
	r := reader("Cookie: " + sdata + "\r\n\n")
	want := MIMEHeader{"Cookie": {{"Cookie", " " + sdata, sdata}}}
	m, err := r.ReadMIMEHeader()
	if err != nil {
		t.Errorf("ReadMIMEHeader() err=%v, want=nil", err)
	}
	if diff := cmp.Diff(want, m); diff != "" {
		t.Errorf("ReadMIMEHeader() results differs: (-want +got)\n%s", diff)
	}
}

// Test that we read slightly-bogus MIME headers seen in the wild,
// with spaces before colons, and spaces in keys.
func TestReadMIMEHeader_nonCompliant(t *testing.T) {
	// Invalid HTTP response header as sent by an Axis security
	// camera: (this is handled by IE, Firefox, Chrome, curl, etc.)
	r := reader("Foo: bar\r\n" +
		"Content-Language: en\r\n" +
		"SID : 0\r\n" +
		"Audio Mode : None\r\n" +
		"Privilege : 127\r\n\r\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{
		"Foo":              {{"Foo", " bar", "bar"}},
		"Content-Language": {{"Content-Language", " en", "en"}},
		"Sid":              {{"SID ", " 0", "0"}},
		"Audio Mode":       {{"Audio Mode ", " None", "None"}},
		"Privilege":        {{"Privilege ", " 127", "127"}},
	}
	if err != nil {
		t.Errorf("ReadMIMEHeader() err=%v, want=nil", err)
	}
	if diff := cmp.Diff(want, m); diff != "" {
		t.Errorf("ReadMIMEHeader() results differs: (-want +got)\n%s", diff)
	}
}

func TestReadMIMEHeader_malformed(t *testing.T) {
	inputs := []string{
		"No colon first line\r\nFoo: foo\r\n\r\n",
		" No colon first line with leading space\r\nFoo: foo\r\n\r\n",
		"\tNo colon first line with leading tab\r\nFoo: foo\r\n\r\n",
		" First: line with leading space\r\nFoo: foo\r\n\r\n",
		"\tFirst: line with leading tab\r\nFoo: foo\r\n\r\n",
		"Foo: foo\r\nNo colon second line\r\n\r\n",
	}

	for _, input := range inputs {
		r := reader(input)
		if m, err := r.ReadMIMEHeader(); err == nil {
			t.Errorf("ReadMIMEHeader(%q) = %v, %v; want nil, err", input, m, err)
		}
	}
}

// Test that continued lines are properly trimmed. Issue 11204.
func TestReadMIMEHeader_trimContinued(t *testing.T) {
	// In this header, \n and \r\n terminated lines are mixed on purpose.
	// We expect each line to be trimmed (prefix and suffix) before being concatenated.
	// Keep the spaces as they are.
	r := reader("" + // for code formatting purpose.
		"a:\n" +
		" 0 \r\n" +
		"b:1 \t\r\n" +
		"c: 2\r\n" +
		" 3\t\n" +
		"  \t 4  \r\n\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{
		"A": {{"a", "\n 0 ", "0"}},
		"B": {{"b", "1 \t", "1"}},
		"C": {{"c", " 2\n 3\t\n  \t 4  ", "2 3 4"}},
	}
	if err != nil {
		t.Errorf("ReadMIMEHeader() err=%v, want=nil", err)
	}
	if diff := cmp.Diff(want, m); diff != "" {
		t.Errorf("ReadMIMEHeader() results differs: (-want +got)\n%s", diff)
	}
}
