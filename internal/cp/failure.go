package cp

import (
	"net/http"

	"github.com/larytet/zscaler/internal/store"
)

func (a *API) failureView(tenant string) map[string]any {
	f := a.Store.FailureModeOf(tenant)
	return map[string]any{"on_stale": f.OnStale, "on_log_failure": f.OnLogFailure, "stale_after": "15m (the node's --stale-after)",
		"explanation": []string{
			"on_stale: when an enforcement node has not heard from the control plane for the staleness window, \"deny\" refuses new private-app sessions and new web requests; \"cached\" lets them go on under the last policy the node holds.",
			"on_log_failure: when a node cannot write its decision log, \"deny\" refuses new sessions and requests; \"allow\" lets them go on, and the decisions made meanwhile are not recorded on that node.",
			"Sessions that are already open are never cut by either. Revocations and policy changes that the node has not received cannot take effect while it is cut off: a long window with \"cached\" is a window in which a revoked device or disabled user may still get in on a new session.",
			"Every decision made while going on despite a fault is recorded with the note state-stale-cached or log-sink-down-allowed.",
		}}
}

// putFailureMode sets what happens to new sessions when a node is unhealthy (NFR-012).
func (a *API) putFailureMode(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in store.FailureMode
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	before := a.failureView(c.tenant)
	f, err := a.Store.SetFailureMode(c.tenant, in)
	if err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	a.log(c, "failure-mode.put", "", before, f)
	return a.failureView(c.tenant), nil
}

func (a *API) getFailureMode(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.failureView(c.tenant), nil
}
