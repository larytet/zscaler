package cp

import (
	"net/http"
	"strings"

	"github.com/larytet/zscaler/internal/tenancy"
)

// putTenancy sets the tenancy restrictions (DATA-002a): which Microsoft, Google and Slack tenants people
// may sign in to from managed devices. The platform adds the vendors' headers on decrypted sign-in traffic.
func (a *API) putTenancy(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in tenancy.Config
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	cfg, err := tenancy.Validate(in)
	if err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	var before any
	if old := a.Store.Tenancy(c.tenant); old != nil {
		before = old
	}
	if err := a.Store.SetTenancy(c.tenant, &cfg); err != nil {
		return nil, err
	}
	a.log(c, "tenancy.put", "", before, cfg)
	return a.tenancyView(c.tenant), nil
}

// tenancyView returns the restrictions and what stops them from working in the tenant's current setup.
func (a *API) tenancyView(tenant string) map[string]any {
	cfg := a.Store.Tenancy(tenant)
	out := map[string]any{"configured": !cfg.Empty()}
	if cfg.Empty() {
		return out
	}
	out["microsoft"], out["google"], out["slack"] = cfg.Microsoft, cfg.Google, cfg.Slack
	var warnings []string
	ic, _ := a.Store.Inspection(tenant)
	if !ic.Enabled {
		warnings = append(warnings, "TLS inspection is off: the restriction headers can only be added to decrypted traffic, so nothing is restricted. Turn inspection on.")
	} else {
		for _, h := range cfg.AllHosts() {
			for _, x := range ic.Exempt {
				x = strings.ToLower(x)
				if h == x || strings.HasSuffix(h, "."+x) || strings.HasSuffix(x, "."+h) {
					warnings = append(warnings, "The sign-in host "+h+" is on the inspection exempt list ("+x+"): it is tunnelled unseen, so it is not restricted.")
				}
			}
		}
	}
	warnings = append(warnings,
		"This adds each vendor's documented header; the vendor enforces it. A device that does not use this platform's proxy, or a browser profile that signs in elsewhere, is not restricted.",
		"The hosts and header names follow the vendors' documentation as the author knows it and have not been checked against the live services: check them before relying on this.")
	out["warnings"] = warnings
	return out
}

func (a *API) getTenancy(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return a.tenancyView(c.tenant), nil
}

func (a *API) deleteTenancy(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	before := a.Store.Tenancy(c.tenant)
	if err := a.Store.SetTenancy(c.tenant, nil); err != nil {
		return nil, err
	}
	a.log(c, "tenancy.delete", "", before, nil)
	return map[string]bool{"configured": false}, nil
}
