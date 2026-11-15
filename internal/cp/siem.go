package cp

import (
	"net/http"

	"github.com/larytet/zscaler/internal/siem"
)

// putSIEM sets where the tenant's decision records and audit events are streamed (INT-004). The
// token and the private CA are write-only: no endpoint returns them, and the audit log omits them.
func (a *API) putSIEM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.SIEM == nil {
		return nil, fail(503, "unavailable", "log streaming is not enabled on this control plane")
	}
	var in struct {
		siem.Config
		Decisions *bool `json:"decisions"`
		Audit     *bool `json:"audit"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	cfg := in.Config
	cfg.Decisions, cfg.Audit = in.Decisions == nil || *in.Decisions, in.Audit == nil || *in.Audit
	if old := a.Store.SIEM(c.tenant); old != nil && old.Kind == cfg.Kind {
		if cfg.Token == "" && old.URL == cfg.URL {
			cfg.Token = old.Token // an update that does not mention the token keeps it
		}
		if cfg.CAPEM == "" {
			cfg.CAPEM = old.CAPEM
		}
	}
	cfg, err := siem.Validate(cfg, a.SIEM.AllowLoopback)
	if err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	if err := a.SIEM.Configure(c.tenant, &cfg); err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	if err := a.Store.SetSIEM(c.tenant, &cfg); err != nil {
		return nil, err
	}
	a.log(c, "siem.put", cfg.Kind, nil, map[string]any{"url": cfg.URL, "addr": cfg.Addr, "proto": cfg.Proto, "decisions": cfg.Decisions, "audit": cfg.Audit}) // never the token
	return siemView(cfg), nil
}

func siemView(c siem.Config) map[string]any {
	return map[string]any{"configured": true, "kind": c.Kind, "url": c.URL, "header": c.Header, "addr": c.Addr, "proto": c.Proto,
		"has_token": c.Token != "", "has_ca": c.CAPEM != "", "decisions": c.Decisions, "audit": c.Audit}
}

func (a *API) getSIEM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	cfg := a.Store.SIEM(c.tenant)
	if cfg == nil {
		return map[string]any{"configured": false}, nil
	}
	out := siemView(*cfg)
	if a.SIEM != nil {
		if st, ok := a.SIEM.Stats(c.tenant); ok {
			out["stats"] = st
		}
	}
	return out, nil
}

func (a *API) deleteSIEM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.SIEM != nil {
		a.SIEM.Configure(c.tenant, nil)
	}
	if err := a.Store.SetSIEM(c.tenant, nil); err != nil {
		return nil, err
	}
	a.log(c, "siem.delete", "", nil, nil)
	return map[string]bool{"configured": false}, nil
}

// testSIEM sends one test event and says whether the receiver took it.
func (a *API) testSIEM(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	if a.SIEM == nil {
		return nil, fail(503, "unavailable", "log streaming is not enabled on this control plane")
	}
	if err := a.SIEM.Test(c.tenant); err != nil {
		return nil, fail(502, "delivery_failed", err.Error())
	}
	return map[string]bool{"delivered": true}, nil
}
