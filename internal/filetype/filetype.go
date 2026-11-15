// Package filetype tells what kind of file a transfer carries (ZIA-013): from the file's name, the
// declared content type and the first bytes of the content (its signature). A rule can then block
// uploads or downloads of a kind, such as executables or archives, however the file is named.
//
// Detection is by signature and name, not by opening files: an executable inside an archive, or
// inside an encrypted document, is seen only as the archive or document it is inside.
package filetype

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"path"
	"sort"
	"strings"
)

// Classes a rule can name.
const (
	Executable  = "executable"      // programs and installers (Windows, Linux, macOS)
	Script      = "script"          // shell, PowerShell, batch, VBScript, HTA and similar, by name
	Archive     = "archive"         // zip, rar, 7z, tar, gzip, bzip2, xz
	DiskImage   = "disk-image"      // iso, img, dmg, vhd
	OfficeMacro = "office-macro"    // Office documents that carry macros (.docm, .xlsm, .pptm) by name
	OfficeDoc   = "office-document" // Word, Excel and PowerPoint documents, old and new
	PDF         = "pdf"
	Image       = "image"
	AudioVideo  = "audio-video"
	Disguised   = "disguised" // content that is one kind under a name or type that says another
)

// Known lists the class names.
var Known = []string{Executable, Script, Archive, DiskImage, OfficeMacro, OfficeDoc, PDF, Image, AudioVideo, Disguised}

// IsKnown accepts a class name, or "ext:.abc" for one extension.
func IsKnown(name string) bool {
	if strings.HasPrefix(name, "ext:") {
		e := strings.TrimPrefix(name, "ext:")
		return len(e) >= 2 && len(e) <= 12 && e[0] == '.' && strings.Trim(e[1:], "abcdefghijklmnopqrstuvwxyz0123456789") == ""
	}
	for _, k := range Known {
		if k == name {
			return true
		}
	}
	return false
}

var byExt = map[string]string{
	".exe": Executable, ".dll": Executable, ".msi": Executable, ".com": Executable, ".scr": Executable, ".sys": Executable, ".so": Executable,
	".app": Executable, ".pkg": Executable, ".deb": Executable, ".rpm": Executable, ".apk": Executable, ".jar": Executable, ".bin": Executable,
	".ps1": Script, ".bat": Script, ".cmd": Script, ".vbs": Script, ".vbe": Script, ".wsf": Script, ".hta": Script, ".sh": Script, ".jse": Script, ".lnk": Script,
	".zip": Archive, ".rar": Archive, ".7z": Archive, ".tar": Archive, ".gz": Archive, ".tgz": Archive, ".bz2": Archive, ".xz": Archive, ".cab": Archive,
	".iso": DiskImage, ".img": DiskImage, ".dmg": DiskImage, ".vhd": DiskImage, ".vhdx": DiskImage,
	".docm": OfficeMacro, ".xlsm": OfficeMacro, ".pptm": OfficeMacro, ".dotm": OfficeMacro, ".xlam": OfficeMacro,
	".doc": OfficeDoc, ".docx": OfficeDoc, ".xls": OfficeDoc, ".xlsx": OfficeDoc, ".ppt": OfficeDoc, ".pptx": OfficeDoc, ".dot": OfficeDoc,
	".pdf": PDF,
	".jpg": Image, ".jpeg": Image, ".png": Image, ".gif": Image, ".bmp": Image, ".webp": Image, ".tif": Image, ".tiff": Image, ".ico": Image,
	".mp3": AudioVideo, ".mp4": AudioVideo, ".avi": AudioVideo, ".mov": AudioVideo, ".mkv": AudioVideo, ".wav": AudioVideo, ".webm": AudioVideo, ".flac": AudioVideo,
}

var byMIME = map[string]string{
	"application/x-msdownload": Executable, "application/x-dosexec": Executable, "application/vnd.microsoft.portable-executable": Executable,
	"application/x-msi": Executable, "application/x-executable": Executable, "application/x-mach-binary": Executable, "application/java-archive": Executable,
	"application/zip": Archive, "application/x-zip-compressed": Archive, "application/x-rar-compressed": Archive, "application/vnd.rar": Archive,
	"application/x-7z-compressed": Archive, "application/x-tar": Archive, "application/gzip": Archive, "application/x-gzip": Archive, "application/x-bzip2": Archive,
	"application/x-iso9660-image": DiskImage, "application/x-apple-diskimage": DiskImage,
	"application/pdf":    PDF,
	"application/msword": OfficeDoc, "application/vnd.ms-excel": OfficeDoc, "application/vnd.ms-powerpoint": OfficeDoc,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   OfficeDoc,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         OfficeDoc,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": OfficeDoc,
	"application/vnd.ms-word.document.macroenabled.12":                          OfficeMacro,
	"application/vnd.ms-excel.sheet.macroenabled.12":                            OfficeMacro,
	"application/vnd.ms-powerpoint.presentation.macroenabled.12":                OfficeMacro,
	"application/x-sh": Script, "application/x-bat": Script, "application/hta": Script,
}

// signature kinds found at the start of content
func sniff(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("MZ")): // Windows programs and libraries
		return Executable
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return Executable
	case bytes.HasPrefix(head, []byte{0xFE, 0xED, 0xFA, 0xCE}), bytes.HasPrefix(head, []byte{0xFE, 0xED, 0xFA, 0xCF}),
		bytes.HasPrefix(head, []byte{0xCE, 0xFA, 0xED, 0xFE}), bytes.HasPrefix(head, []byte{0xCF, 0xFA, 0xED, 0xFE}), bytes.HasPrefix(head, []byte{0xCA, 0xFE, 0xBA, 0xBE}):
		return Executable // Mach-O (and Java class files share the last signature)
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("PK\x05\x06")):
		return Archive
	case bytes.HasPrefix(head, []byte("Rar!\x1a\x07")), bytes.HasPrefix(head, []byte("7z\xbc\xaf\x27\x1c")),
		bytes.HasPrefix(head, []byte{0x1f, 0x8b}), bytes.HasPrefix(head, []byte("BZh")), bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		return Archive
	case bytes.HasPrefix(head, []byte("%PDF-")):
		return PDF
	case bytes.HasPrefix(head, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}): // old Office (compound file)
		return OfficeDoc
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF}), bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")), bytes.HasPrefix(head, []byte("GIF87a")),
		bytes.HasPrefix(head, []byte("GIF89a")), bytes.HasPrefix(head, []byte("BM")) && len(head) > 14:
		return Image
	}
	return ""
}

// Detect returns the sorted classes of one file. name may be empty; contentType is the declared
// type; head is the start of the content (a few hundred bytes are enough).
func Detect(name, contentType string, head []byte) []string {
	set := map[string]bool{}
	nameClass, mimeClass := "", ""
	ext := ""
	if name != "" {
		ext = strings.ToLower(path.Ext(strings.TrimRight(name, " .")))
		if c, ok := byExt[ext]; ok {
			nameClass = c
			set[c] = true
		}
		if ext != "" {
			set["ext:"+ext] = true
		}
	}
	if contentType != "" {
		if mt, _, err := mime.ParseMediaType(contentType); err == nil {
			if c, ok := byMIME[strings.ToLower(mt)]; ok {
				mimeClass = c
				set[c] = true
			} else if strings.HasPrefix(mt, "image/") {
				mimeClass = Image
				set[Image] = true
			} else if strings.HasPrefix(mt, "audio/") || strings.HasPrefix(mt, "video/") {
				mimeClass = AudioVideo
				set[AudioVideo] = true
			}
		}
	}
	sig := sniff(head)
	if sig != "" {
		set[sig] = true
	}
	// an Office document is a zip file: a .docx whose content is a zip is what it says, not an archive to block
	if sig == Archive && (nameClass == OfficeDoc || nameClass == OfficeMacro || nameClass == Executable && ext == ".jar" || ext == ".apk") {
		delete(set, Archive)
	}
	// content that is a program under a name or a type that says something harmless is the case a rule cannot do without
	if sig == Executable {
		for _, claimed := range []string{nameClass, mimeClass} {
			if claimed != "" && claimed != Executable && claimed != Script {
				set[Disguised] = true
			}
		}
		if ext != "" && nameClass == "" && ext != ".exe" && ext != ".dll" {
			set[Disguised] = true
		}
	}
	return sorted(set)
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Upload returns the classes of everything an upload carries: each file of a multipart form, or the
// body itself for any other upload. The body may be truncated: only the start of each part is used.
func Upload(contentType, urlPath string, body []byte) []string {
	set := map[string]bool{}
	mt, params, err := mime.ParseMediaType(contentType)
	if err == nil && strings.HasPrefix(mt, "multipart/") && params["boundary"] != "" {
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for i := 0; i < 64; i++ {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			head, _ := io.ReadAll(io.LimitReader(p, 512))
			io.Copy(io.Discard, p)
			if p.FileName() == "" && p.Header.Get("Content-Type") == "" {
				continue // an ordinary form field
			}
			for _, c := range Detect(p.FileName(), p.Header.Get("Content-Type"), head) {
				set[c] = true
			}
		}
		return sorted(set)
	}
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	return Detect(urlPath, contentType, head)
}

// Download returns the classes of a response: the file name in Content-Disposition (or else the end of
// the URL path), the declared type and the first bytes.
func Download(disposition, urlPath, contentType string, head []byte) []string {
	name := ""
	if disposition != "" {
		if _, params, err := mime.ParseMediaType(disposition); err == nil {
			name = params["filename"]
		}
	}
	if name == "" {
		name = path.Base(urlPath)
	}
	if len(head) > 512 {
		head = head[:512]
	}
	return Detect(name, contentType, head)
}

// Match reports whether any class in found is one of the names a rule asks for.
func Match(want, found []string) bool {
	for _, w := range want {
		for _, f := range found {
			if w == f {
				return true
			}
		}
	}
	return false
}
