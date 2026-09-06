# mruby-ktls

Linux and FreeBSD can encrypt and decrypt TLS records inside the kernel.
The feature is called kTLS. You give the kernel the keys a TLS 1.3
handshake agreed on, and after that an ordinary `send` on that socket
goes out as a TLS record and an ordinary `recv` returns plaintext. No
TLS library sits between your program and the socket, so `sendfile`,
`splice` and io_uring writes work as they do on a plain socket.

This gem does the handshake and produces those keys. It never opens,
reads or writes a socket: you hand it the handshake bytes that arrived,
it hands you the bytes that must go out, and you send them however you
like. When the handshake is done it gives you the two `crypto_info`
blobs the kernel wants, or installs them for you on a descriptor you
name.

What you need:

- a kernel with the tls module - `modprobe tls`, or `ktls_load_module`
- OpenSSL 3.0 or later, built with kTLS (see below)

What it does not do: verify a peer certificate (`ktls_keys_client`
carries no trust store), speak TLS 1.2 or older, or take the socket
away from you.

## The loop, in C

Handshake bytes come from the socket and go back to it. Nothing else
does.

```c
#include <ktls.h>

int serve(int fd, const char *cert, size_t clen, const char *key, size_t klen)
{
  ktls_keys *k = ktls_keys_server(cert, clen, key, klen);
  const char *alpn[] = { "h2", "http/1.1" };
  ktls_keys_set_alpn(k, alpn, 2);

  ktls_exchange *x = ktls_exchange_open(k, KTLS_SERVER);
  unsigned char buf[16384];
  ktls_step step = KTLS_READING;

  while (step != KTLS_DONE) {
    if (ktls_exchange_step(x, &step) != 0) goto fail;   /* ktls_last_error() */

    for (size_t n; (n = ktls_exchange_take(x, buf, sizeof buf)) > 0; )
      if (write(fd, buf, n) < 0) goto fail;             /* your own send */

    if (step == KTLS_READING) {
      ssize_t r = read(fd, buf, sizeof buf);            /* your own recv */
      if (r <= 0) goto fail;
      if (ktls_exchange_feed(x, buf, (size_t)r) != 0) goto fail;
    }
  }

  /* Tickets and any early application data, before the kernel takes over. */
  size_t early = ktls_exchange_backlog(x, buf, sizeof buf);

  if (ktls_offload(x, fd) != 0) goto fail;              /* ULP + both keys */
  ktls_exchange_free(x);                                 /* keep it to rekey */
  ktls_keys_free(k);

  /* From here the socket speaks TLS by itself. */
  write(fd, "HTTP/1.1 204 No Content\r\n\r\n", 27);
  return 0;

fail:
  fprintf(stderr, "ktls: %s\n", ktls_last_error());
  ktls_exchange_free(x);
  ktls_keys_free(k);
  return -1;
}
```

Build it against the machine's OpenSSL:

```sh
cc -std=c11 -D_GNU_SOURCE -O2 -o server server.c src/ktls.c -Iinclude \
   $(pkg-config --cflags --libs libssl) -lcrypto
```

A reactor that owns its descriptors takes the two blobs instead of
`ktls_offload`, and submits the `setsockopt` itself:

```c
size_t len;
const void *tx = ktls_crypto_info(x, KTLS_TX, &len);   /* read LAST */
setsockopt(fd, ktls_sol_tls(), ktls_optname(KTLS_TX), tx, len);
const void *rx = ktls_crypto_info(x, KTLS_RX, &len);
setsockopt(fd, ktls_sol_tls(), ktls_optname(KTLS_RX), rx, len);
```

`ktls_attach_ulp(fd)` must come first on Linux; `ktls_offload` does it
for you.

## The same in C++

`include/ktls.hpp` wraps the same calls in two move-only handles that
free themselves. No exceptions, one call deep, same order.

```cpp
#include <ktls.hpp>

bool serve(int fd, std::string_view cert, std::string_view key)
{
  auto keys = ktls::Keys::server(cert.data(), cert.size(), key.data(), key.size());
  if (!keys) return false;
  const char* alpn[] = { "h2", "http/1.1" };
  keys.set_alpn(alpn, 2);

  auto x = ktls::Exchange::open(keys, KTLS_SERVER);
  if (!x) return false;

  unsigned char buf[16384];
  ktls_step step = KTLS_READING;
  while (step != KTLS_DONE) {
    if (x.step(&step) != 0) return false;
    for (size_t n; (n = x.take(buf, sizeof buf)) > 0; )
      if (::write(fd, buf, n) < 0) return false;
    if (step == KTLS_READING) {
      ssize_t r = ::read(fd, buf, sizeof buf);
      if (r <= 0 || x.feed(buf, size_t(r)) != 0) return false;
    }
  }

  x.backlog(buf, sizeof buf);
  return x.offload(fd) == 0;          // both handles free on scope exit
}
```

```sh
c++ -std=c++20 -D_GNU_SOURCE -O2 -o server server.cpp src/ktls.c -Iinclude \
    $(pkg-config --cflags --libs libssl) -lcrypto
```

## The same in Ruby

```ruby
keys = KTLS::Keys.server(cert_pem, key_pem)
keys.alpn = %w[h2 http/1.1]

x = KTLS::Exchange.new(keys, :server)
loop do
  st = x.step
  while (out = x.take) && !out.empty?
    sock.write(out)
  end
  break if st == :done
  x.feed(sock.sysread(16384)) if st == :reading
end

x.backlog
x.offload(sock.fileno)
sock.write("HTTP/1.1 204 No Content\r\n\r\n")
```

`KTLS.available?`, `KTLS.initialized?` and `KTLS.load_module` answer
what the kernel offers. `x.alpn`, `x.cipher`, `x.record_limit` and
`x.next_key(:tx)` are there for a connection that lives long.

## Rekeying, after a few gigabytes

AES-GCM may encrypt only so many records under one key. `ktls_record_limit`
says how many; ChaCha answers 0, which means no limit worth counting.
The kernel writes the records once the socket is offloaded, so the
count is yours to keep: every `sendmsg` is at least one record and at
most `ceil(len / 16384)`.

Keep the exchange for the life of the connection instead of freeing it.
`ktls_exchange_release` gives up the SSL and its buffers - the large
part - and keeps what a rekey needs.

```c
ktls_offload(x, fd);
ktls_exchange_release(x);              /* keep x, drop the SSL */
uint64_t limit = ktls_record_limit(x); /* 0 = never */

/* ... while serving, after every send: */
records += (len + 16383) / 16384;
if (limit && records >= limit) {
  ktls_next_key(x, KTLS_TX);           /* one notch, sequence back to 0 */
  size_t n;
  const void *tx = ktls_crypto_info(x, KTLS_TX, &n);
  setsockopt(fd, ktls_sol_tls(), ktls_optname(KTLS_TX), tx, n);
  records = 0;
}
```

The peer may turn its own key at any time. On an offloaded socket that
arrives as a record which is not application data, so it is seen only
with `recvmsg`:

```c
struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                      .msg_control = cmsgbuf, .msg_controllen = sizeof cmsgbuf };
ssize_t r = recvmsg(fd, &msg, 0);

struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
if (c && c->cmsg_type == ktls_record_type_cmsg()) {
  switch (ktls_record_type(CMSG_DATA(c), c->cmsg_len - CMSG_LEN(0))) {
    case KTLS_RECORD_HANDSHAKE:                 /* a KeyUpdate */
      ktls_next_key(x, KTLS_RX);
      { size_t n; const void *rx = ktls_crypto_info(x, KTLS_RX, &n);
        setsockopt(fd, ktls_sol_tls(), ktls_optname(KTLS_RX), rx, n); }
      break;
    case KTLS_RECORD_ALERT: /* close_notify, or worse */ break;
    case KTLS_RECORD_DATA:  /* the stream */ break;
    default: break;
  }
}
```

In C++ it is `x.record_limit()`, `x.next_key(KTLS_TX)` and
`x.crypto_info(KTLS_TX, &n)`; in Ruby `x.record_limit`,
`x.next_key(:tx)` and `x.crypto_info(:tx)`.

## Rules

- `take` after every `step`, including one that answers `:reading`.
- `backlog` after `:done`, on both sides, before `crypto_info`.
- `crypto_info` last.
- Read an offloaded socket with `recvmsg`, never `recv`: a record that
  is not application data answers `EIO` there.
- Keep the exchange while the connection lives if you will rekey;
  `ktls_exchange_release` drops the large part of it.

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
