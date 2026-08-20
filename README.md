# mruby-ktls

A TLS handshake that exists only to hand the wire to the kernel.

The stack is Amazon's, built to the **minimum that carries kTLS**:
[AWS-LC](https://github.com/aws/aws-lc)'s libcrypto (its libssl is
never built - s2n is the TLS layer) under
[s2n-tls](https://github.com/aws/s2n-tls), both static, both pinned as
submodules. After `negotiate` the kernel takes the record layer
(`s2n_connection_ktls_enable_send/recv`) and the socket speaks plain
`send`/`recv` - or io_uring submissions - while s2n leaves the data
path.

## KTLS::Socket - the socket API, subclassed

For everyone who just wants a socket: `KTLS::Socket < TCPSocket`
adopts an existing connection and replaces ONLY what must stay under
s2n's eyes - `#write` routes through `s2n_send` (after the handover
that submits through the OFFLOADED socket: kernel crypto, record
accounting, KeyUpdates when due), `#recv` through `s2n_recv` (an
incoming KeyUpdate is processed, not EIO). Everything else is
inherited untouched; `IO.select` works because the fd is real. The
three caveats from the table below dissolve here by construction.

```ruby
tls = KTLS::Socket.attach(sock, config, :server)  # adopts a dup of the fd
tls.handshake                  # blocking convenience; steps, then offload
tls.write("hello")             # kernel-encrypted when ktls_available?
line = tls.recv(4096)
tls.close                      # close_notify, then the fd
```

Reactors use `#handshake_step` (or `KTLS::Connection` directly) and
keep the raw-fd escape - with its duties.

## Shape

Made for a one-thread nonblocking reactor: the fd goes `O_NONBLOCK`
at attach, `negotiate` steps and never sleeps (self-service blinding),
and both ends of a handshake can be driven from a single thread.

```ruby
scfg = KTLS::Config.server(cert_pem, key_pem)
# TLS 1.3 is MANDATORY by default (policy AWS-CRT-SDK-TLSv1.3,
# minimum 1.3); #policy= overrides, knowing why.

conn = KTLS::Connection.new(scfg, sock, :server)
loop do
  case conn.negotiate
  when :done    then break
  when :reading then wait_readable(sock)   # your reactor's wait
  when :writing then wait_writable(sock)
  end
end

conn.enable_ktls_send   # the kernel owns the send path now
conn.enable_ktls_recv   # ... and the receive path
sock.write(bytes)  # a plain write IS a TLS record from here on
```

`KTLS::Connection#send/#recv` speak through s2n for whatever runs
before - or without - the handover.

Needing no keys and no s2n: `KTLS.supported?` (a probe that DOES the
thing - a loopback TCP pair, `TCP_ULP` set to `"tls"` - instead of
guessing from versions) and `KTLS.ulp(io)` attaching the ULP raw.

## Scope lines

- **Client verification is currently DISABLED** (`KTLS::Config.client`
  is for loopback tests and pinned deployments that verify
  themselves). A trust-store API is the next slab; nothing here
  pretends to be one.
- TLS 1.3 is mandatory, and s2n's ONLY 1.3 handover path is
  `s2n_config_ktls_enable_unsafe_tls13`. That call is not the absence
  of KeyUpdate support - it IS s2n's KeyUpdate-over-kTLS machinery
  (send a KeyUpdate through the offloaded socket and re-setsockopt
  TLS_TX; process a received one and re-setsockopt TLS_RX). "unsafe"
  labels three caveats, all about raw-fd use, and the embedder owns
  them here - decided knowingly:

  | Caveat | Owner's duty |
  |---|---|
  | AES-GCM key limit (~388GB/direction) counted only for s2n_send traffic | Cap bytes per connection below the limit, or prefer CHACHA20-POLY1305 (`Connection#cipher` says which applies) |
  | Incoming KeyUpdate = EIO on a raw read | Treat as end of connection (errors kill the connection, never the process) |
  | Re-key needs a second setsockopt | Kernel >= 6.14 |
- `Connection.new` sets `TCP_NODELAY` (best-effort): Nagle holds the
  second of s2n's CCS+Finished writes hostage to a delayed ACK, and a
  nonblocking stepper spins its budget away in microseconds while 58
  bytes sit in the kernel for 40ms. Found as a live stall, kept as a
  sentence.
- Why kTLS at all, measured on the old tree: throughput parity with
  userspace TLS, RSS is the win, and splice into a kTLS socket works -
  file bodies never touch userspace.

## Not AF_ALG

kTLS is often confused with the kernel's OTHER crypto interface.
AF_ALG (`CONFIG_CRYPTO_USER_API`) is the generic crypto socket API -
deprecated for Linux 7.2 after a steady CVE stream ("Copy Fail",
CVE-2026-31431, sat in `algif_aead`), and already disabled by
distributions. kTLS is the TLS ULP (`CONFIG_TLS`), a separate
subsystem that calls kernel crypto internally and takes no AF_ALG
detour. `CRYPTO_USER_API=n` with `CONFIG_TLS=y` is exactly the
intended pairing: their door closed, this one open.

## Requirements

Linux with `CONFIG_TLS` for the handover (probed at runtime, never
assumed); the s2n handshake itself runs anywhere Linux. Non-Linux
compiles: `supported?` answers `false`, operations raise
`NotImplementedError`. Build needs cmake (AWS-LC ships pregenerated
sources; no Go, no Perl).

## Tests

`rake test` clones mruby master and proves: the probe answers, a
loopback handshake completes single-threaded and stepped, application
data round-trips through s2n, and - where `CONFIG_TLS` exists - a
plain socket write after `enable_ktls_send` arrives as a valid TLS
record.

## License

Apache-2.0
