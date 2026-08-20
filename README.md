# mruby-ktls

Kernel TLS for mruby sockets: after a TLS handshake has produced key
material, the kernel takes over the record layer (`TLS_TX`/`TLS_RX`),
and the socket speaks plain `send`/`recv` - or io_uring sends - while
the kernel encrypts. No userspace TLS stack touches the data path.

## Scope

**In scope**: everything after the keys exist.

- `KTLS.supported?` - a real probe (a loopback TCP pair, `TCP_ULP`
  set to `"tls"`), not a version guess. Autoloads the `tls` module
  where module loading is permitted.
- `KTLS.ulp(io)` - attach the TLS upper-layer protocol to an
  ESTABLISHED TCP socket. First step of every kTLS setup; raises
  `SystemCallError` with the kernel's reason when refused.
- Planned, in order: `KTLS.tx(io, cipher, key, iv, salt, seq)` /
  `KTLS.rx(...)` installing `tls12_crypto_info_*` for AES-128-GCM,
  AES-256-GCM and CHACHA20-POLY1305 (TLS 1.2 and 1.3 layouts), and
  `KTLS.info(io)` for what is installed.

**Out of scope, permanently**: the handshake. kTLS does not do
handshakes and neither does this gem - bring keys from whatever
negotiated them (OpenSSL, mbedTLS, a session-ticket store). This gem
is the boundary between "keys exist" and "the kernel owns the wire".

## Why

An io_uring reactor wants one send per response and zero userspace
copies. A userspace TLS record layer breaks both. With kTLS the
reactor's data path stays byte-identical to its cleartext path - the
send is the same send.

## Requirements

Linux with `CONFIG_TLS` (module or built-in), kernel >= 4.13 for
TLS_TX, >= 4.17 for TLS_RX; TLS 1.3 crypto-info layouts need >= 5.10.
On non-Linux the gem compiles, `KTLS.supported?` answers `false`, and
every operation raises `NotImplementedError`.

## License

Apache-2.0
