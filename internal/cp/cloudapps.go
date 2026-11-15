package cp

import (
	"errors"
	"net/http"

	"github.com/larytet/zscaler/internal/cloudapps"
	"github.com/larytet/zscaler/internal/store"
)

// listCloudApps shows the apps a rule can name: the built-in catalogue and the tenant's own (ZIA-011).
func (a *API) listCloudApps(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	return map[string]any{"apps": a.Store.CloudCatalog(c.tenant).List(), "actions": cloudapps.Actions,
		"note": "The built-in apps are hand-made from what the author knows of each service and have not been checked against the live services; a request this catalogue does not recognise as an action is not matched. Add or replace an app with PUT /v1/cloud-apps/{id}."}, nil
}

// putCloudApp adds one of the tenant's own apps, or replaces a built-in one.
func (a *API) putCloudApp(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	var in cloudapps.App
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.ID != "" && in.ID != r.PathValue("id") {
		return nil, fail(400, "invalid", "the id in the body must match the one in the address")
	}
	in.ID = r.PathValue("id")
	app, err := cloudapps.Validate(in)
	if err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	if err := a.Store.PutCloudApp(c.tenant, app); err != nil {
		return nil, fail(400, "invalid", err.Error())
	}
	a.log(c, "cloud-app.put", app.ID, nil, app)
	return app, nil
}

func (a *API) deleteCloudApp(w http.ResponseWriter, r *http.Request, c ctxInfo) (any, error) {
	id := r.PathValue("id")
	if err := a.Store.DeleteCloudApp(c.tenant, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fail(404, "not_found", "you have no app of your own with that id (built-in apps cannot be deleted, only replaced)")
		}
		return nil, fail(409, "in_use", err.Error())
	}
	a.log(c, "cloud-app.delete", id, nil, nil)
	return map[string]string{"deleted": id}, nil
}
