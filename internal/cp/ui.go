package cp

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui
var uiFS embed.FS

// mountUI serves the console. It is static: all data comes from the API with
// the admin's own token, so the page itself carries no secrets.
func (a *API) mountUI(m *http.ServeMux) {
	sub, _ := fs.Sub(uiFS, "ui")
	files := http.FileServer(http.FS(sub))
	secure := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hd := w.Header()
			hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
			hd.Set("X-Content-Type-Options", "nosniff")
			hd.Set("X-Frame-Options", "DENY")
			hd.Set("Referrer-Policy", "no-referrer")
			hd.Set("Cache-Control", "no-store")
			h.ServeHTTP(w, r)
		})
	}
	m.Handle("GET /ui/", secure(http.StripPrefix("/ui/", files)))
	m.Handle("GET /{$}", secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})))
}
