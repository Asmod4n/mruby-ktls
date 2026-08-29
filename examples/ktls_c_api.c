/* The C surface, proven by doing: a whole TLS 1.3 exchange between two
 * ktls_exchange objects in one thread, with no socket anywhere. What
 * comes out is what the kernel gets - so the strongest check available
 * without a tls ULP is that the server's SEND keys and the client's
 * RECEIVE keys are the same bytes. */
#include "ktls.h"

#include <linux/tls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  char *buf = malloc(8192);
  *len = fread(buf, 1, 8192, f);
  fclose(f);
  return buf;
}

/* One direction of the pump: take whatever a side owes and feed it to
 * the other. Returns how many bytes moved. */
static size_t pump(ktls_exchange *from, ktls_exchange *to)
{
  unsigned char buf[16384];
  size_t moved = 0;
  for (;;) {
    const size_t n = ktls_exchange_take(from, buf, sizeof(buf));
    if (n == 0) break;
    if (ktls_exchange_feed(to, buf, n) != 0) { printf("feed: %s\n", ktls_last_error()); exit(1); }
    moved += n;
  }
  return moved;
}

int main(int argc, char **argv)
{
  const char *suites = argc > 1 ? argv[1] : NULL;
  size_t certlen = 0, keylen = 0;
  char *cert = slurp("examples/cert.pem", &certlen);
  char *key = slurp("examples/key.pem", &keylen);

  ktls_keys *server_keys = ktls_keys_server(cert, certlen, key, keylen);
  ok(server_keys != NULL, "ktls_keys_server loads a PEM chain and key");
  if (server_keys == NULL) { printf("  %s\n", ktls_last_error()); return 1; }

  static const char *const offered[] = { "h2", "http/1.1" };
  ok(ktls_keys_set_alpn(server_keys, offered, 2) == 0, "ktls_keys_set_alpn takes h2 and http/1.1");
  if (suites != NULL) {
    ok(ktls_keys_set_ciphers(server_keys, suites) == 0, "ktls_keys_set_ciphers overrides the order");
  }

  ktls_keys *client_keys = ktls_keys_client();
  ok(client_keys != NULL, "ktls_keys_client builds a config without a trust store");
  ok(ktls_keys_set_alpn(client_keys, offered, 2) == 0, "the client offers the same two");

  ktls_exchange *s = ktls_exchange_open(server_keys, KTLS_SERVER);
  ktls_exchange *c = ktls_exchange_open(client_keys, KTLS_CLIENT);
  ok(s != NULL && c != NULL, "two exchanges open, neither naming a descriptor");

  /* Single-threaded and stepped, the shape a one-thread reactor drives. */
  ktls_step ss = KTLS_READING, cs = KTLS_READING;
  int rounds = 0;
  while ((ss != KTLS_DONE || cs != KTLS_DONE) && rounds++ < 64) {
    if (ktls_exchange_step(c, &cs) != 0) { printf("client: %s\n", ktls_last_error()); return 1; }
    pump(c, s);
    if (ktls_exchange_step(s, &ss) != 0) { printf("server: %s\n", ktls_last_error()); return 1; }
    pump(s, c);
  }
  ok(ss == KTLS_DONE && cs == KTLS_DONE, "both sides reach KTLS_DONE, stepped, one thread");
  ok(rounds < 64, "and reach it without spinning");

  /* Both sides drain first: on a server this is a request that came in
   * the same flight as the client's Finished, on a client it is the
   * NewSessionTickets - records that must be CONSUMED before the
   * kernel is told where the sequence stands. */
  unsigned char backlog[4096];
  ok(ktls_exchange_backlog(s, backlog, sizeof(backlog)) == 0,
     "the server has no backlog - this client pipelined nothing");
  (void) ktls_exchange_backlog(c, backlog, sizeof(backlog));

  size_t alen = 0;
  const char *alpn = ktls_exchange_alpn(s, &alen);
  ok(alpn != NULL && alen == 2 && memcmp(alpn, "h2", 2) == 0,
     "ALPN settles on h2 - the server's order decides");

  size_t stx = 0, srx = 0, ctx_ = 0, crx = 0;
  const struct tls12_crypto_info_chacha20_poly1305 *sti = ktls_crypto_info(s, KTLS_TX, &stx);
  const struct tls12_crypto_info_chacha20_poly1305 *sri = ktls_crypto_info(s, KTLS_RX, &srx);
  const struct tls12_crypto_info_chacha20_poly1305 *cti = ktls_crypto_info(c, KTLS_TX, &ctx_);
  const struct tls12_crypto_info_chacha20_poly1305 *cri = ktls_crypto_info(c, KTLS_RX, &crx);
  ok(sti && sri && cti && cri, "every direction yields a crypto_info");

  const struct tls_crypto_info *head = (const struct tls_crypto_info *) sti;
  printf("  (AES instructions: %s, negotiated %s)\n",
         ktls_aes_is_fast() ? "yes" : "no", ktls_exchange_cipher(s));
  ok(head->version == TLS_1_3_VERSION, "the kernel is told TLS 1.3");
  const int want = suites != NULL
                       ? (strstr(suites, "CHACHA") == suites + 4 || suites[4] == 'C'
                              ? TLS_CIPHER_CHACHA20_POLY1305
                              : TLS_CIPHER_AES_GCM_128)
                       : (ktls_aes_is_fast() ? TLS_CIPHER_AES_GCM_128
                                             : TLS_CIPHER_CHACHA20_POLY1305);
  ok(head->cipher_type == want, "and the suite that was asked for");
  ok(stx == (head->cipher_type == TLS_CIPHER_AES_GCM_128
                 ? sizeof(struct tls12_crypto_info_aes_gcm_128)
                 : sizeof(struct tls12_crypto_info_chacha20_poly1305)),
     "the blob is the size that cipher's struct has");

  /* The proof: what the server encrypts with IS what the client
   * decrypts with. A wrong label, a swapped direction or a bad HkdfLabel
   * would all break exactly here. */
  ok(memcmp(sti, cri, stx) == 0, "the server's SEND blob IS the client's RECEIVE blob");
  ok(memcmp(cti, sri, ctx_) == 0, "and the other way round");
  ok(memcmp(sti, cti, stx) != 0, "the two directions differ");

  unsigned char zero[64] = { 0 };
  ok(memcmp((const unsigned char *) sti + sizeof(*head), zero, 16) != 0,
     "the key is not zeroes");

  /* Session tickets are NewSessionTicket records, written under the
   * application key the moment the handshake ends - so the kernel may
   * not be told to start at zero. Both sides count independently and
   * must land on the same number: the server counts what it wrote,
   * the client counts what it read. */
  const uint64_t s_tx = ktls_record_sequence(s, KTLS_TX);
  const uint64_t c_rx = ktls_record_sequence(c, KTLS_RX);
  printf("  (server wrote %llu application records after the handshake, "
         "client read %llu)\n", (unsigned long long) s_tx, (unsigned long long) c_rx);
  ok(s_tx > 0, "the tickets DID move the sequence - zero would be nonce reuse");
  ok(s_tx == c_rx, "server TX sequence == client RX sequence");
  const unsigned char *s_seq = (const unsigned char *) sti + stx - 8;
  ok(s_seq[7] == (unsigned char) s_tx && s_seq[0] == 0,
     "the sequence is written big-endian, as the kernel reads it");
  ok(ktls_record_sequence(s, KTLS_RX) == 0,
     "the server read no application record - the client sent none");

  /* RFC 8446 4.6.3, without OpenSSL: turn the secret one notch and the
   * two sides must STILL agree, or a KeyUpdate would break the
   * connection instead of continuing it. */
  const uint64_t limit = ktls_record_limit(s);
  printf("  (records allowed under one key: %llu%s)\n", (unsigned long long) limit,
         limit == 0 ? " - no limit worth counting" : "");
  unsigned char before[64];
  memcpy(before, sti, stx);
  ok(ktls_next_key(s, KTLS_TX) == 0, "ktls_next_key turns the server's send secret");
  ok(ktls_next_key(c, KTLS_RX) == 0, "and the client's receive secret");
  size_t s2 = 0, c2 = 0;
  const void *sti2 = ktls_crypto_info(s, KTLS_TX, &s2);
  const void *cri2 = ktls_crypto_info(c, KTLS_RX, &c2);
  ok(sti2 != NULL && cri2 != NULL && s2 == c2, "both hand out a fresh blob");
  ok(memcmp(sti2, cri2, s2) == 0, "and after the update the two STILL match");
  ok(memcmp(sti2, before, s2) != 0, "the new key is not the old one");
  ok(((const unsigned char *) sti2)[s2 - 1] == 0,
     "and the sequence restarts at zero, as a key change leaves it");
  ok(ktls_record_sequence(s, KTLS_TX) == 0,
     "which record_sequence says too - the blob and the getter agree");

  /* The refusal, where the tls subsystem is not initialized. */
  if (!ktls_initialized()) {
    ok(ktls_offload(s, 0) == -1, "ktls_offload refuses by name without the tls module");
    printf("  (%s)\n", ktls_last_error());
  } else {
    printf("  (this kernel has kTLS - the handover itself is testable here)\n");
  }

  ktls_exchange_free(s);
  ktls_exchange_free(c);
  ktls_keys_free(server_keys);
  ktls_keys_free(client_keys);
  printf("\n%s\n", fails == 0 ? "all ok" : "FAILURES");
  return fails != 0;
}
