package filetype

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"
)

var (
	pe    = append([]byte("MZ\x90\x00\x03"), make([]byte, 100)...)
	elf   = append([]byte("\x7fELF\x02\x01"), make([]byte, 100)...)
	zip_  = append([]byte("PK\x03\x04"), make([]byte, 100)...)
	pdf   = []byte("%PDF-1.7\n1 0 obj")
	jpeg  = []byte{0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, 'J', 'F', 'I', 'F'}
	plain = []byte("hello, this is just text")
)

func has(got []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			return false
		}
	}
	return true
}

func TestDetectBySignatureNameAndType(t *testing.T) { // AGT-025 (ZIA-013)
	cases := []struct {
		name, ctype string
		head        []byte
		want        []string
		not         []string
	}{
		{"setup.exe", "application/octet-stream", pe, []string{Executable, "ext:.exe"}, []string{Disguised}},
		{"tool", "", elf, []string{Executable}, nil},
		{"invoice.pdf.exe", "", pe, []string{Executable, "ext:.exe"}, []string{PDF}},
		{"backup.zip", "application/zip", zip_, []string{Archive}, nil},
		{"report.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", zip_, []string{OfficeDoc}, []string{Archive}},
		{"budget.xlsm", "", zip_, []string{OfficeMacro}, []string{Archive}},
		{"x.jar", "", zip_, []string{Executable}, []string{Archive}},
		{"deploy.ps1", "text/plain", plain, []string{Script}, nil},
		{"installer.iso", "", nil, []string{DiskImage}, nil},
		{"doc.pdf", "application/pdf", pdf, []string{PDF}, []string{Executable, Disguised}},
		{"photo.jpg", "image/jpeg", jpeg, []string{Image}, []string{Executable, Disguised}},
		{"notes.txt", "text/plain", plain, nil, []string{Executable, Archive, Disguised, Script}},
		{"", "", nil, nil, []string{Executable}},
		// the case that matters: a program under a harmless name or type
		{"holiday.jpg", "image/jpeg", pe, []string{Executable, Disguised}, nil},
		{"statement.pdf", "application/pdf", pe, []string{Executable, Disguised}, nil},
		{"data.dat", "", pe, []string{Executable, Disguised}, nil},
		{"notes.txt", "text/plain", elf, []string{Executable, Disguised}, nil},
		// names are not fooled by trailing dots or spaces, or by upper case
		{"SETUP.EXE ", "", nil, []string{Executable}, nil},
		{"payload.exe.", "", nil, []string{Executable}, nil},
	}
	for _, c := range cases {
		got := Detect(c.name, c.ctype, c.head)
		if !has(got, c.want...) {
			t.Errorf("%q %q: got %v, want %v", c.name, c.ctype, got, c.want)
		}
		for _, n := range c.not {
			if has(got, n) {
				t.Errorf("%q %q: %v must not include %s", c.name, c.ctype, got, n)
			}
		}
	}
}

func TestUploadsMultipartAndRaw(t *testing.T) { // AGT-025
	form := func(files map[string][]byte, fields map[string]string) (string, []byte) {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		for k, v := range fields {
			w.WriteField(k, v)
		}
		for name, content := range files {
			fw, _ := w.CreateFormFile("file", name)
			fw.Write(content)
		}
		w.Close()
		return w.FormDataContentType(), b.Bytes()
	}
	ct, body := form(map[string][]byte{"cv.pdf": pdf, "tool.exe": pe}, map[string]string{"name": "Jane", "note": "MZ is not a file"})
	got := Upload(ct, "/upload", body)
	if !has(got, PDF, Executable) {
		t.Fatalf("both files must be seen: %v", got)
	}
	ct, body = form(map[string][]byte{"cv.pdf": pdf}, map[string]string{"note": "MZ"})
	if got := Upload(ct, "/upload", body); has(got, Executable) {
		t.Fatalf("a form field that starts with MZ is not a program: %v", got)
	}
	ct, body = form(map[string][]byte{"holiday.jpg": pe}, nil)
	if got := Upload(ct, "/upload", body); !has(got, Executable, Disguised) {
		t.Fatalf("a program uploaded as a picture: %v", got)
	}
	// a raw upload: the type, the path and the start of the body
	if got := Upload("application/octet-stream", "/files/run.exe", pe); !has(got, Executable) {
		t.Fatalf("%v", got)
	}
	if got := Upload("application/json", "/api/items", []byte(`{"a":1}`)); has(got, Executable, Archive, Script) || len(got) > 1 {
		t.Fatalf("an ordinary API call must not look like a file: %v", got)
	}
	// a broken multipart body does not panic and yields nothing
	if got := Upload("multipart/form-data; boundary=zzz", "/u", []byte("garbage")); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if got := Upload("multipart/form-data", "/u", nil); got == nil && false {
		t.Fatal("unreachable")
	}
}

func TestDownloadsUseTheDispositionNameFirst(t *testing.T) { // AGT-025
	if got := Download(`attachment; filename="update.exe"`, "/dl/abc123", "application/octet-stream", pe); !has(got, Executable) {
		t.Fatalf("%v", got)
	}
	if got := Download("", "/files/readme.txt", "text/plain", plain); has(got, Executable) {
		t.Fatalf("%v", got)
	}
	if got := Download(`attachment; filename="photo.png"`, "/x", "image/png", pe); !has(got, Disguised) {
		t.Fatalf("a program sent as a picture: %v", got)
	}
	// no name at all: the signature still decides
	if got := Download("", "/", "application/octet-stream", elf); !has(got, Executable) {
		t.Fatalf("%v", got)
	}
}

func TestKnownNames(t *testing.T) {
	for _, n := range []string{"executable", "archive", "disguised", "ext:.exe", "ext:.7z"} {
		if !IsKnown(n) {
			t.Errorf("%s should be known", n)
		}
	}
	for _, n := range []string{"", "exe", "ext:exe", "ext:.", "ext:.EXE", "ext:.a b", "malware", "ext:" + strings.Repeat(".a", 10)} {
		if IsKnown(n) {
			t.Errorf("%q should not be known", n)
		}
	}
	if !Match([]string{"ext:.exe"}, []string{"executable", "ext:.exe"}) || Match([]string{"pdf"}, []string{"archive"}) || Match(nil, []string{"archive"}) {
		t.Error("Match")
	}
}
