package webproxy

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/larytet/zscaler/internal/broker"
)

// CaptureMaxBody is the most of each body that is kept (ZIA-022b).
const CaptureMaxBody = 64 << 10

// redactedHeaders never leave the enforcement node in a capture.
var redactedHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true, "x-csrf-token": true, "x-amz-security-token": true,
}

// captureHeaders flattens headers, replacing credential-bearing ones and cutting long values.
func captureHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.Join(h[k], ", ")
		switch {
		case redactedHeaders[strings.ToLower(k)]:
			v = "[redacted]"
		case len(v) > 512:
			v = v[:512] + "...[cut]"
		}
		out[k] = v
	}
	return out
}

// takePrefix reads up to max bytes of a body and hands the body back whole, so forwarding is
// unaffected. truncated is true if more than max bytes exist.
func takePrefix(body io.ReadCloser, max int) (prefix []byte, restored io.ReadCloser, truncated bool) {
	if body == nil || body == http.NoBody {
		return nil, body, false
	}
	buf, _ := io.ReadAll(io.LimitReader(body, int64(max)+1))
	if len(buf) > max {
		return buf[:max], readCloser{io.MultiReader(bytes.NewReader(buf), body), body}, true
	}
	return buf, io.NopCloser(bytes.NewReader(buf)), false
}

// captureRecord builds the record to send. The query string is dropped from the path because
// queries often carry tokens; the capture says so.
func captureRecord(base broker.Record, rule, verdict string, q *http.Request, reqBody []byte,
	status int, respHeaders http.Header, respBody []byte, truncated bool) broker.Record {
	path := q.URL.Path
	if q.URL.RawQuery != "" {
		path += "?[query removed]"
	}
	c := &broker.Capture{Rule: rule, Method: q.Method, Host: strings.ToLower(q.Host), Path: path, Verdict: verdict, Status: status,
		ReqHeaders: captureHeaders(q.Header), Truncated: truncated}
	if len(reqBody) > 0 {
		c.ReqBody = base64.StdEncoding.EncodeToString(reqBody)
	}
	if respHeaders != nil {
		c.RespHeaders = captureHeaders(respHeaders)
	}
	if len(respBody) > 0 {
		c.RespBody = base64.StdEncoding.EncodeToString(respBody)
	}
	rec := base
	rec.TS, rec.Kind, rec.Action, rec.Event = time.Now().UTC(), "capture", "info", "open"
	rec.Reason, rec.Target, rec.Capture = "", "", c
	rec.DLP, rec.Health = nil, nil
	return rec
}
