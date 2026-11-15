// Package devenv tells developer tools about the tenant's TLS inspection (ZIA-034, basic).
// Command-line tools and language runtimes keep their own list of trusted roots, so with
// inspection on they fail on every HTTPS request until they are pointed at the tenant's CA
// and at the agent's proxy. This builds the environment that does it.
package devenv

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Tool is a tool, and the environment variable it reads for extra or replacement roots.
type Tool struct {
	Name string
	Var  string
	// Bundle is true when the variable replaces the tool's roots (so it must hold the public
	// roots as well as the tenant CA) and false when it only adds to them.
	Bundle bool
}

// Tools lists what the environment covers. It is a list of what is known to honour the
// variable, not a promise about every version: JVM tools, Docker's daemon and the system
// keychain of some tools need other steps (see Uncovered).
var Tools = []Tool{
	{"curl", "CURL_CA_BUNDLE", true},
	{"OpenSSL-based tools, Go programs, Ruby, Terraform", "SSL_CERT_FILE", true},
	{"Python requests, httpx, Azure CLI", "REQUESTS_CA_BUNDLE", true},
	{"pip", "PIP_CERT", true},
	{"Node.js, npm scripts, yarn, pnpm", "NODE_EXTRA_CA_CERTS", false},
	{"npm", "npm_config_cafile", true},
	{"git", "GIT_SSL_CAINFO", true},
	{"AWS CLI and SDKs", "AWS_CA_BUNDLE", true},
	{"Cargo (Rust)", "CARGO_HTTP_CAINFO", true},
	{"Deno", "DENO_CERT", true},
	{"gcloud", "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", true},
	{"gRPC clients", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", true},
	{"conda", "CONDA_SSL_VERIFY", true},
	{"Composer (PHP)", "COMPOSER_CAFILE", true},
}

// Uncovered says what a person must still do by hand.
var Uncovered = []string{
	"Java tools (Maven, Gradle, sbt): import the certificate into the JVM trust store with keytool.",
	"Docker and containerd: install the certificate for the daemon (/etc/docker/certs.d) and restart it.",
	"Tools that pin certificates (some package registries' clients, banking tools): put the domain on the exempt list.",
	"Programs that ignore HTTP_PROXY and HTTPS_PROXY: they bypass the proxy and are not inspected.",
}

// SystemBundlePaths are where operating systems keep their public roots as one PEM file.
var SystemBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // macOS, Alpine
}

// BuildBundle returns the public roots followed by the tenant CA. used is the file the public
// roots came from, or "" if none was found; in that case the result holds only the tenant CA
// and the caller must not point replace-the-roots variables at it.
func BuildBundle(tenantCA []byte, paths []string) (bundle []byte, used string) {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil && bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
			out := append(bytes.TrimRight(b, "\n"), '\n')
			return append(out, tenantCA...), p
		}
	}
	return append([]byte(nil), tenantCA...), ""
}

// Exports returns shell lines. bundleOK says whether bundleFile holds the public roots too.
func Exports(caFile, bundleFile string, bundleOK bool, proxyURL string) []string {
	var out []string
	add := func(k, v string) { out = append(out, fmt.Sprintf("export %s=%s", k, shellQuote(v))) }
	add("HTTP_PROXY", proxyURL)
	add("HTTPS_PROXY", proxyURL)
	add("http_proxy", proxyURL)
	add("https_proxy", proxyURL)
	add("NO_PROXY", "localhost,127.0.0.1,::1")
	add("no_proxy", "localhost,127.0.0.1,::1")
	seen := map[string]bool{}
	for _, t := range Tools {
		if t.Var == "" || seen[t.Var] {
			continue
		}
		seen[t.Var] = true
		switch {
		case !t.Bundle:
			add(t.Var, caFile)
		case bundleOK:
			add(t.Var, bundleFile)
		}
	}
	sort.Strings(out[6:]) // proxies first, then the variables in a stable order
	return out
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
