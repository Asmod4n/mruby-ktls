/* The half this machine cannot prove: after the keys go into the
 * socket, a PLAIN write must arrive as TLS on the other side. Run it
 * on a kernel with CONFIG_TLS - it says so by name where there is none.
 *
 *   cc -o ktls_handover test/ktls_handover.c src/ktls.c -Iinclude \
 *      $(pkg-config --cflags --libs openssl)
 *   ./ktls_handover [ciphersuite]
 */
#include "ktls.h"

#include <arpa/inet.h>
#include <linux/tls.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails = 0;

static void ok(int cond, const char *what)
{
  printf("%-58s %s\n", what, cond ? "ok" : "FAIL");
  if (!cond) fails++;
}

static char *slurp(const char *path, size_t *len)
{
  FILE *f = fopen(path, "rb");
  if (f == NULL) { perror(path); exit(1); }
  char *buf = malloc(65536);
  *len = fread(buf, 1, 65536, f);
  fclose(f);
  return buf;
}

/* A connected TCP pair on loopback: kTLS is a TCP ULP, a socketpair
 * cannot carry it. */
static void tcp_pair(int *a, int *b)
{
  const int lst = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(lst, (struct sockaddr *) &sa, sizeof(sa));
  listen(lst, 1);
  socklen_t sl = sizeof(sa);
  getsockname(lst, (struct sockaddr *) &sa, &sl);
  *a = socket(AF_INET, SOCK_STREAM, 0);
  connect(*a, (struct sockaddr *) &sa, sizeof(sa));
  *b = accept(lst, NULL, NULL);
  close(lst);
}

static void carry(ktls_exchange *from, int fd_from)
{
  unsigned char buf[16384];
  for (;;) {
    const size_t n = ktls_exchange_take(from, buf, sizeof(buf));
    if (n == 0) break;
    if (write(fd_from, buf, n) != (ssize_t) n) { perror("write"); exit(1); }
  }
}

static void collect(ktls_exchange *to, int fd_to)
{
  unsigned char buf[16384];
  const ssize_t n = read(fd_to, buf, sizeof(buf));
  if (n > 0 && ktls_exchange_feed(to, buf, (size_t) n) != 0) {
    printf("feed: %s\n", ktls_last_error());
    exit(1);
  }
}

int main(int argc, char **argv)
{
  if (!ktls_initialized()) {
    printf("this kernel has no tls ULP - %s\n",
           ktls_available() ? "it ships one: modprobe tls, or run ktls_load_module()"
                            : "and no module to load. Nothing to prove here.");
    return 77;
  }

  size_t clen = 0, klen = 0;
  char *cert = slurp("test/cert.pem", &clen);
  char *key = slurp("test/key.pem", &klen);

  ktls_keys *sk = ktls_keys_server(cert, clen, key, klen);
  ktls_keys *ck = ktls_keys_client();
  if (sk == NULL || ck == NULL) { printf("%s\n", ktls_last_error()); return 1; }
  if (argc > 1) {
    ktls_keys_set_ciphers(sk, argv[1]);
    ktls_keys_set_ciphers(ck, argv[1]);
  }

  int cfd, sfd;
  tcp_pair(&cfd, &sfd);

  ktls_exchange *s = ktls_exchange_open(sk, KTLS_SERVER);
  ktls_exchange *c = ktls_exchange_open(ck, KTLS_CLIENT);

  ktls_step ss = KTLS_READING, cs = KTLS_READING;
  int rounds = 0;
  while ((ss != KTLS_DONE || cs != KTLS_DONE) && rounds++ < 64) {
    if (ktls_exchange_step(c, &cs) != 0) { printf("client: %s\n", ktls_last_error()); return 1; }
    carry(c, cfd);
    if (cs == KTLS_READING && ss == KTLS_DONE) collect(c, cfd);
    if (ktls_exchange_step(s, &ss) != 0) { printf("server: %s\n", ktls_last_error()); return 1; }
    carry(s, sfd);
    if (ss == KTLS_READING) collect(s, sfd);
    if (cs == KTLS_READING) collect(c, cfd);
  }
  ok(ss == KTLS_DONE && cs == KTLS_DONE, "the exchange finishes over a real socket");
  printf("  (negotiated %s)\n", ktls_exchange_cipher(s));

  unsigned char backlog[4096];
  (void) ktls_exchange_backlog(s, backlog, sizeof(backlog));
  (void) ktls_exchange_backlog(c, backlog, sizeof(backlog));

  /* THE handover. Both directions or neither. */
  ok(ktls_offload(s, sfd) == 0, "the server's socket takes both keys");
  if (fails) printf("  %s\n", ktls_last_error());
  ok(ktls_offload(c, cfd) == 0, "the client's socket takes both keys");
  if (fails) printf("  %s\n", ktls_last_error());

  ktls_exchange_free(s);
  ktls_exchange_free(c);
  ktls_keys_free(sk);
  ktls_keys_free(ck);

  /* From here the library is gone and the descriptors are ordinary. */
  static const char kHello[] = "GET / HTTP/1.1\r\nHost: proof\r\n\r\n";
  ok(write(cfd, kHello, sizeof(kHello) - 1) == (ssize_t) sizeof(kHello) - 1,
     "a PLAIN write on the client socket");

  char got[512];
  const ssize_t n = read(sfd, got, sizeof(got));
  ok(n == (ssize_t) sizeof(kHello) - 1 && memcmp(got, kHello, (size_t) n) == 0,
     "arrives as itself on the server socket - encrypted by the kernel");

  static const char kBack[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
  ok(write(sfd, kBack, sizeof(kBack) - 1) == (ssize_t) sizeof(kBack) - 1,
     "and a plain write back");
  const ssize_t m = read(cfd, got, sizeof(got));
  ok(m == (ssize_t) sizeof(kBack) - 1 && memcmp(got, kBack, (size_t) m) == 0,
     "arrives on the client - both directions are the kernel's now");

  close(cfd);
  close(sfd);
  printf("\n%s\n", fails == 0 ? "all ok - the kernel is the record layer" : "FAILURES");
  return fails != 0;
}
