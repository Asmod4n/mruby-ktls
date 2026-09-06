# mruby-ktls

Agree TLS 1.3 keys, hand them to the kernel, get out of the way.

This library never touches a socket. It takes the bytes that arrived and
returns the bytes that must go out. At the end it produces the two
`crypto_info` blobs for `setsockopt`, and from there the kernel is the
record layer: plain `send` and `recv` are TLS.

## Surface

C — `include/ktls.h`:

```c
ktls_keys *k = ktls_keys_server(cert, clen, key, klen);
ktls_keys_set_alpn(k, (const char *[]){ "h2", "http/1.1" }, 2);

ktls_exchange *x = ktls_exchange_open(k, KTLS_SERVER);
ktls_exchange_feed(x, from_peer, n);
ktls_exchange_step(x, &step);          /* DONE | READING | WRITING */
ktls_exchange_take(x, buf, sizeof buf);

ktls_exchange_backlog(x, buf, sizeof buf);
ktls_offload(x, fd);                   /* or ktls_crypto_info for your own reactor */
ktls_exchange_free(x);
```

C++ — `include/ktls.hpp`: move-only handles, no exceptions.

Ruby — `KTLS::Keys` and `KTLS::Exchange`:

```ruby
keys = KTLS::Keys.server(cert_pem, key_pem)
keys.alpn = %w[h2 http/1.1]

x = KTLS::Exchange.new(keys, :server)
x.feed(bytes_from_peer)
x.step                       # :done, :reading, :writing
x.take                       # String, "" when nothing is owed
x.backlog                    # drain on both sides before the handover
x.crypto_info(:tx)           # the setsockopt payload
```

## Rules

- `take` after every `step`, including one that answers `:reading`.
- `backlog` after `:done`, on both sides, before `crypto_info`.
- `crypto_info` last.
- Read a kernel-owned socket with `recvmsg`, never `recv`: 23 is data,
  21 an alert, 22 a KeyUpdate. `ktls_record_type` reads the control
  message; `ktls_next_key` answers a KeyUpdate.

## What it speaks

TLS 1.3 with `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`.
AES first where the machine has the instructions, ChaCha first otherwise;
`ktls_keys_set_ciphers` overrides.

Peer verification is off: `ktls_keys_client` carries no trust store.

## Linux and FreeBSD

| | Linux | FreeBSD |
|---|---|---|
| attach | `setsockopt(TCP_ULP, "tls")` | nothing |
| is it there | `/proc/net/tls_stat` | `kern.ipc.tls.enable` |
| turn it on | `modprobe tls`, or `ktls_load_module` | the same sysctl |
| receiving | always | where `TCP_RXTLS_ENABLE` exists |

`ktls_attach_ulp` is a no-op on FreeBSD. The FreeBSD half has not been
compiled on FreeBSD.

## OpenSSL

The machine's, OpenSSL 3.0 or later, built with kTLS. Nothing is
vendored. `rake openssl` prints which one was chosen.

| | |
| --- | --- |
| openSUSE | `zypper install libopenssl-3-devel` |
| Fedora | `dnf install openssl-devel` |
| Arch | `pacman -S openssl` |
| Debian, Ubuntu | `apt install libssl-dev` |

Two knobs:

```sh
OPENSSL_PKG_CONFIG=openssl3 rake
PKG_CONFIG_PATH=$HOME/.local/openssl/lib64/pkgconfig:$PKG_CONFIG_PATH rake
```

## Tasks

```sh
rake test        # the Ruby surface
rake exchange    # a whole exchange from C and C++, no socket
rake handover    # a real loopback pair; exits 77 without a tls ULP
```

## License

Apache-2.0
