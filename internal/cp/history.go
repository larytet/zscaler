package cp

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/larytet/zscaler/internal/decisions"
)

// parseWhen accepts a full time (RFC 3339) or a date (the whole of that UTC day for "to").
func parseWhen(s string, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return t, err
	}
	if endOfDay {
		t = t.Add(24*time.Hour - time.Nanosecond)
	}
	return t, nil
}

// decisionHistory searches the decision records kept on disk for the retention period (ADM-006,
// FW-010, ADM-007). Query: from, to (RFC 3339 or a date), user, app, action, kind, limit, cursor.
func (a *API) decisionHistory(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var arch *decisions.Archive
	if a.Decisions != nil {
		arch = a.Decisions.Archive()
	}
	if arch == nil {
		return nil, fail(503, "unavailable", "decision records are not being kept on disk by this control plane")
	}
	q := r.URL.Query()
	dq := decisions.Query{User: q.Get("user"), App: q.Get("app"), Action: q.Get("action"), Kind: q.Get("kind"), Cursor: q.Get("cursor")}
	var err error
	if v := q.Get("from"); v != "" {
		if dq.From, err = parseWhen(v, false); err != nil {
			return nil, fail(400, "invalid", "from must be a date (2026-11-01) or a time (2026-11-01T09:00:00Z)")
		}
	}
	if v := q.Get("to"); v != "" {
		if dq.To, err = parseWhen(v, true); err != nil {
			return nil, fail(400, "invalid", "to must be a date (2026-11-01) or a time (2026-11-01T09:00:00Z)")
		}
	}
	if !dq.To.IsZero() && !dq.From.IsZero() && dq.To.Before(dq.From) {
		return nil, fail(400, "invalid", "to is before from")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return nil, fail(400, "invalid", "limit must be 1 to 1000")
		}
		dq.Limit = n
	}
	res, err := arch.Query(c.tenant, dq) // the tenant comes from the token only
	if errors.Is(err, decisions.ErrBadCursor) {
		return nil, fail(400, "invalid", "that cursor is not valid")
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"records": res.Records, "next_cursor": res.Next, "partial": res.Partial,
		"oldest": res.Oldest, "retention_days": int(arch.Retention / (24 * time.Hour))}, nil
}
