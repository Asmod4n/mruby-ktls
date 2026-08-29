# mruby-ktls

Agree keys, hand them to the kernel, get out of the way.

This library never touches a socket. It is fed the bytes that arrived
and hands back the bytes that must go out, so whoever owns the
descriptor keeps owning it — io_uring submissions against a direct
descriptor included. When the exchange is done it produces the two
`crypto_info` blobs the kernel wants, and from the `setsockopt` that
carries them **the kernel is the record layer**: plain `send`/`recv`
are TLS, and nothing here sits in the data path.

```c
ktls_keys *k = ktls_keys_server(cert, clen, key, klen);
ktls_keys_set_alpn(k, (const char *[]){ "h2", "http/1.1" }, 2);

ktls_exchange *x = ktls_exchange_open(k, KTLS_SERVER);   /* no descriptor */
ktls_exchange_feed(x, from_peer, n);                     /* what came in  */
ktls_exchange_step(x, &step);                            /* DONE | READING | WRITING */
ktls_exchange_take(x, buf, sizeof buf);                  /* what must go out */

ktls_exchange_backlog(x, buf, sizeof buf);               /* drain, both sides */
const void *tx = ktls_crypto_info(x, KTLS_TX, &len);     /* read LAST */
ktls_exchange_free(x);                                   /* done for good */
```

Three languages, one surface: `include/ktls.h` for C, `include/ktls.hpp`
for C++ (move-only handles, no exceptions, every method one call deep),
and `KTLS::Keys` / `KTLS::Exchange` for Ruby. `src/mrb_ktls.c` is a
caller like any other.

```ruby
keys = KTLS::Keys.server(cert_pem, key_pem)
keys.alpn = %w[h2 http/1.1]

x = KTLS::Exchange.new(keys, :server)
x.feed(bytes_from_peer)
case x.step
when :done then # ...
when :reading, :writing then # ...
end
x.take                       # String, "" when nothing is owed
x.backlog                    # drain on BOTH sides before the next line
x.crypto_info(:tx)           # the setsockopt payload, as bytes
```

## The order, and why it is an order

```
step  until :done       — :done only comes when take owes nothing
backlog                 — on BOTH sides
crypto_info             — the sequence is settled here
setsockopt              — ULP, then TLS_TX and TLS_RX
free
```

Each line is a trap the type system cannot close:

- **`:done` waits for `take`.** Bytes still owed are ciphertext OpenSSL
  already produced under the handshake keys. The kernel would encrypt
  them a second time.
- **`backlog` on both sides.** RFC 8446 4.6.1 lets a peer put
  application data in the same flight as its Finished, and a server
  writes its NewSessionTickets right after the handshake. Those are
  records under the application key; a side that has not consumed them
  disagrees with the other about where the record sequence stands.
- **`crypto_info` last.** A TLS 1.3 key change resets the sequence, so
  the kernel is told where the application keys already stood. Getting
  this wrong is nonce reuse, not a wrong answer.

## What it speaks

TLS 1.3, and two suites that both hash with SHA-256:

| | `TLS_AES_128_GCM_SHA256` | `TLS_CHACHA20_POLY1305_SHA256` |
|---|---|---|
| kernel kTLS | yes | yes |
| NIC offload (`ethtool tls-hw-tx-offload`) | **yes** | no |
| without AES instructions | slower, and timing-sensitive | constant-time by construction |
| records under one key | 2^24.5 (RFC 8446 5.5) | none anyone reaches |

AES first where the machine has the instructions, ChaCha first
otherwise; `ktls_keys_set_ciphers` overrides. `TLS_AES_256_GCM_SHA384`
is not offered: 14 rounds instead of 10 for security nobody can reach,
and it would have dragged SHA-384 into the key schedule.

A KeyUpdate costs the 32 bytes of secret the exchange still holds and
nothing else — `ktls_next_key` turns it one notch with RFC 8446 7.2's
`"traffic upd"` label. That is what makes AES-GCM's limit answerable
rather than fatal.

## Linux and FreeBSD

Two kernels carry TLS and they agree on nothing but the idea.

| | Linux | FreeBSD |
|---|---|---|
| attach | `setsockopt(TCP_ULP, "tls")` | nothing - the keys go straight on |
| is it there | `/proc/net/tls_stat` | `kern.ipc.tls.enable` |
| turn it on | `modprobe tls` (or `ktls_load_module`) | the same sysctl, written |
| the struct | `tls12_crypto_info_*`, one per cipher, material inside | one `struct tls_enable`, pointing at it |
| the iv | split: AES-GCM 4 salt + 8 iv, ChaCha all 12 | never split - all 12, with `iv_len` |
| receiving | always | only where `TCP_RXTLS_ENABLE` exists |

`ktls_attach_ulp` is a no-op on FreeBSD so no caller needs an `#ifdef`,
and `ktls_sol_tls` / `ktls_optname` answer that kernel's level and
names. Where receiving cannot be offloaded, `ktls_offload` refuses by
name rather than handing over half a socket.

The FreeBSD half is written against `sys/sys/ktls.h` and OpenSSL's own
FreeBSD path, and has not been compiled on FreeBSD. It is marked here
so nobody mistakes it for tested.

## Reading a kernel-owned socket

**Never a plain `recv`.** A record that is not application data — an
alert, a KeyUpdate — surfaces as `EIO` there. Read with `recvmsg` and
take the type out of its `TLS_GET_RECORD_TYPE` control message: 23 is
data, 21 an alert, 22 a KeyUpdate to answer. Writing one is the mirror,
`TLS_SET_RECORD_TYPE` on a `sendmsg`, which is also how `close_notify`
goes out without this library.

## Why OpenSSL, and why >= 3.0

Measured, not assumed:

- **s2n-tls** cannot hand ChaCha to the kernel at all.
  `tls/s2n_ktls.c` requires `cipher->set_ktls_info`, and
  `crypto/s2n_aead_cipher_aes_gcm.c` is the only file that defines one
   — in the current pin and in upstream `main`.
- **mbedTLS** has no kTLS code: no hit for `ktls`, `kernel_tls` or
  `TCP_ULP` anywhere in its tree. The key export callback is there, but
  `mbedtls_ssl_tls13_make_traffic_keys` is in a private header.
- **The system OpenSSL is not dependable.** openSUSE ships LibreSSL,
  which has neither `EVP_KDF` TLS13-KDF nor kTLS. Ubuntu ships OpenSSL
  3.0.13 whose `libssl.so.3` exports **no** ktls symbol — kTLS is off
  by default before 3.2, and `BIO_get_ktls_send` is a macro that
  compiles to `(0)`, so a build without it fails silently. `src/ktls.c`
  refuses both, by `#error` and by name.

So OpenSSL is vendored (`deps/openssl`) and built here, **shared** on
purpose — see below.

## Four processes

The process that strangers send requests to holds no keys.

```
supervisor
├── logd        no crypto
├── acme        mruby-url over the system libcurl, whatever TLS the distro has
├── ktls        this library, OpenSSL >= 3, holds the keys and the secrets
└── webserver   no crypto at all
```

`ktls` accepts, runs the exchange, installs ULP + `TLS_TX` + `TLS_RX`
on its own direct descriptor, and pushes that descriptor into the
webserver's ring with `IORING_OP_MSG_RING` / `MSG_SEND_FD` — table to
table, no fd number in either process, ALPN riding along as the
message's data. It keeps its own slot, so when the webserver sees a
record of type 22 it sends one `MSG_DATA` back saying which connection
needs its keys turned.

`acme` is a process of its own because its libcurl brings the
distribution's TLS, and two libcryptos in one address space is a bug
waiting for a link order.

## Tests

`rake test` proves the Ruby surface. `examples/ktls_c_api.c` and
`examples/ktls_cpp_api.cpp` prove the other two, running a whole exchange
between two objects in one thread with no socket anywhere — the check
that carries the rest is that the server's SEND blob **is** the
client's RECEIVE blob, byte for byte, before and after a key update,
under both suites.

`examples/ktls_handover.c` is the half those cannot reach: it needs a
kernel with `CONFIG_TLS`, opens a real loopback pair, hands both
sockets over, frees everything, and then writes plaintext through.

```sh
cc -std=c11 -D_GNU_SOURCE -O2 -o ktls_handover \
   examples/ktls_handover.c src/ktls.c -Iinclude $(pkg-config --cflags --libs openssl)
./ktls_handover
```

It exits 77 and says so where there is no tls ULP, rather than claiming
anything.

## License

Apache-2.0
