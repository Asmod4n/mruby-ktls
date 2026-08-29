// The C++ layer over the same exchange the C test drives: two handles,
// one thread, no socket - and the frees happen by leaving scope.
#include "ktls.hpp"
#include <cstdio>
#include <cstring>
#include <linux/tls.h>

static size_t slurp(const char* p, char* buf, size_t cap) {
  FILE* f = std::fopen(p, "rb");
  const size_t n = std::fread(buf, 1, cap, f);
  std::fclose(f);
  return n;
}

int main() {
  char cert[8192], key[8192];
  const size_t cl = slurp("examples/cert.pem", cert, sizeof cert);
  const size_t kl = slurp("examples/key.pem", key, sizeof key);

  ktls::Keys sk = ktls::Keys::server(cert, cl, key, kl);
  ktls::Keys ck = ktls::Keys::client();
  if (!sk || !ck) { std::printf("keys: %s\n", ktls::last_error()); return 1; }
  const char* alpn[] = {"h2", "http/1.1"};
  sk.set_alpn(alpn, 2);
  ck.set_alpn(alpn, 2);

  ktls::Exchange s = ktls::Exchange::open(sk, KTLS_SERVER);
  ktls::Exchange c = ktls::Exchange::open(ck, KTLS_CLIENT);

  auto pump = [](ktls::Exchange& from, ktls::Exchange& to) {
    unsigned char b[16384];
    for (size_t n; (n = from.take(b, sizeof b)) != 0;) to.feed(b, n);
  };

  ktls_step ss = KTLS_READING, cs = KTLS_READING;
  for (int i = 0; (ss != KTLS_DONE || cs != KTLS_DONE) && i < 64; i++) {
    c.step(&cs); pump(c, s);
    s.step(&ss); pump(s, c);
  }
  unsigned char junk[4096];
  s.backlog(junk, sizeof junk);
  c.backlog(junk, sizeof junk);

  size_t alen = 0, tl = 0, rl = 0;
  const char* a = s.alpn(&alen);
  const void* stx = s.crypto_info(KTLS_TX, &tl);
  const void* crx = c.crypto_info(KTLS_RX, &rl);
  const bool ok = ss == KTLS_DONE && cs == KTLS_DONE && a != nullptr &&
                  std::memcmp(a, "h2", 2) == 0 && stx && crx && tl == rl &&
                  std::memcmp(stx, crx, tl) == 0;
  std::printf("C++ layer: %s (%s, %zu-byte crypto_info, ALPN %.*s)\n",
              ok ? "ok" : "FAIL", s.cipher(), tl, (int)alen, a ? a : "");
  return ok ? 0 : 1;
}
