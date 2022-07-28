# Go TLS self-server

This minimal Go program lacks configuration options and relies on the standard
library's http.ListenAndServeTLS handler. No external dependencies are
required, making this portable across Go runtime variants (BoringCrypto, RHEL
with OpenSSL, &c).

To test the Go TLS server, you first need to install a Go toolchain
environment (e.g., `sudo dnf install -y go`). Then, in this directory,
run `go build`.

Finally, to start a self-server with default configuration:

```
./go-server  -addr ":4433"
```
