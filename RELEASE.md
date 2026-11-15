# Releases: how they are built and how to check one

`make release` (or `ztx-release build`) makes a directory with:

| File | What it is |
|---|---|
| `ztx-agent_<os>_<arch>[.exe]` | The endpoint agent for Linux, macOS (Intel and Apple silicon) and Windows |
| `ztx-connector_linux_<arch>` | The connector, for Linux on amd64 and arm64 |
| `ztx-en_linux_amd64`, `ztx-cp_linux_amd64` | The enforcement node and the control plane |
| `sbom.cdx.json` | The bill of materials (CycloneDX 1.5): each file with its hash, the Go version it was built with, the build settings, and every module inside it |
| `SHA256SUMS` | The SHA-256 of every file above, in the format `sha256sum -c` reads |
| `SHA256SUMS.sig` | An ed25519 signature over `SHA256SUMS` (only when the build was given a key) |

## Check a release you were given

You need the release directory and the vendor's public key (`release-key.pub`).

```
ztx-release verify -dir dist -pub release-key.pub   # signature, checksums, bill of materials, extra or missing files
cd dist && sha256sum -c SHA256SUMS                   # the standard tool agrees
./ztx-agent_linux_amd64 -version                     # says the version that was stamped in
```

`verify` prints every problem it finds (a changed, missing or extra file, a bad signature, a bill of materials that
does not describe the files) and exits with 1 if there is any.

## Check that a release is what the source says (reproducibility)

The programs are built with `-trimpath`, no build identifier, no version-control stamp, stripped symbols and CGO off,
so the same source with the same Go version gives the same bytes in any directory on any machine. Build the same
tag yourself (`VERSION=<the version> make release`, or `ztx-release build -version <the version> -out mine`) and compare
`mine/SHA256SUMS` with the vendor's: they must be identical. This is tested: two builds from two copies of the source
in different directories with different build caches give identical files, checksums and bill of materials.

## Keys

`ztx-release keygen -out release-key` makes a key pair. Publish `release-key.pub` where customers can get it from a
place other than the release itself. Keep `release-key.key` in your build system's secret store or an HSM; never in
the repository. Losing it means issuing a new key and telling customers; there is no revocation list.

## What this does not do

- It does not sign Windows programs with a code-signing certificate or notarise macOS programs: those need
  certificates from Microsoft and Apple, and without them the operating systems will warn when a file is run. The
  signature here is checked with `ztx-release` or by hand, not by the operating system.
- It does not build installers or packages, and there is no update mechanism: a new release is a new directory.
- The bill of materials lists the Go modules inside the binaries. This project has no third-party modules, so it lists
  the Go standard library and this project's own module. It holds no vulnerability data; scan the Go version it names.
- Reproducibility holds for the same Go toolchain version (the one in `go.mod`, named in the bill of materials).
- The Windows agent is built and its disk-usage code is compiled, but this project's tests have not run it on Windows.
