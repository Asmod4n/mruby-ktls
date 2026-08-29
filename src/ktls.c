/* Design decisions live in README.md, under the heading each comment names. */
#include "ktls.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__) || defined(__FreeBSD__)

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#if defined(__linux__)
#include <linux/tls.h>
#include <sys/utsname.h>
#else
#include <sys/ktls.h>
#include <sys/sysctl.h>
#endif
#if defined(__aarch64__)
#include <sys/auxv.h>
#endif
#include <unistd.h>

#include <openssl/opensslv.h>

/* EVP_KDF "TLS13-KDF" is the whole key schedule this file leans on and
 * it arrived in OpenSSL 3.0. LibreSSL reports 0x20000000 here and has
 * neither that nor kTLS, which is why the acme process - whose libcurl
 * brings whatever TLS the distribution shipped - is a process of its
 * own and not this one. */
#if defined(LIBRESSL_VERSION_NUMBER)
#error "ktls needs OpenSSL >= 3.0; this is LibreSSL, which has no TLS13-KDF and no kTLS"
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
#error "ktls needs OpenSSL >= 3.0 for EVP_KDF TLS13-KDF"
#endif

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/ssl.h>

#if defined(__linux__) && !defined(TCP_ULP)
#define TCP_ULP 31
#endif

/* RFC 8446 7.3, and the kernel's tls12_crypto_info_chacha20_poly1305:
 * a 32-byte key, a 12-byte iv with no salt beside it, and a record
 * sequence that starts at zero for the first application record. */
#define KTLS_SECRET_MAX 64

/* The two suites this library offers, named here and not by either
 * kernel's constant: Linux spells them TLS_CIPHER_*, FreeBSD CRYPTO_*,
 * and the exchange has no business knowing which it stands on. */
#define KTLS_AES_GCM_128       1
#define KTLS_CHACHA20_POLY1305 2

/* Spelled per language rather than as C11's keyword: this file is
 * built by a C compiler in the gem and by a C++ one where an embedder
 * drops it into its own build. */
#if defined(__cplusplus)
#define KTLS_PER_THREAD thread_local
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define KTLS_PER_THREAD _Thread_local
#else
#define KTLS_PER_THREAD __thread
#endif

static KTLS_PER_THREAD char ktls_err[256];

static void ktls_fail(const char *what)
{
  const unsigned long e = ERR_get_error();
  if (e != 0) {
    char buf[160];
    ERR_error_string_n(e, buf, sizeof(buf));
    snprintf(ktls_err, sizeof(ktls_err), "%s: %s", what, buf);
  } else {
    snprintf(ktls_err, sizeof(ktls_err), "%s: %s", what, strerror(errno));
  }
}

static void ktls_say(const char *what)
{
  snprintf(ktls_err, sizeof(ktls_err), "%s", what);
}

const char *ktls_last_error(void)
{
  return ktls_err[0] != '\0' ? ktls_err : "no failure recorded";
}

/* ---- what the kernel can do, asked without changing it ----------- */

#if defined(__FreeBSD__)

/* kern.ipc.tls.enable is both questions at once: the sysctl exists
 * where the kernel has the code, and is non-zero where it is on. */
static int ktls_sysctl_int(const char *name, int *out)
{
  size_t len = sizeof(*out);
  return sysctlbyname(name, out, &len, NULL, 0);
}

bool ktls_initialized(void)
{
  int on = 0;
  return ktls_sysctl_int("kern.ipc.tls.enable", &on) == 0 && on != 0;
}

bool ktls_available(void)
{
  int on = 0;
  return ktls_sysctl_int("kern.ipc.tls.enable", &on) == 0;
}

int ktls_load_module(void)
{
  const int on = 1;
  if (sysctlbyname("kern.ipc.tls.enable", NULL, NULL, &on, sizeof(on)) != 0) {
    ktls_fail("sysctl kern.ipc.tls.enable=1");
    return -1;
  }
  return 0;
}

/* Nothing to attach: the keys go straight on. A no-op so the caller
 * needs no #ifdef of its own. */
int ktls_attach_ulp(int fd) { (void) fd; return 0; }

int ktls_sol_tls(void) { return IPPROTO_TCP; }

int ktls_optname(ktls_direction dir)
{
#ifdef TCP_RXTLS_ENABLE
  return dir == KTLS_TX ? TCP_TXTLS_ENABLE : TCP_RXTLS_ENABLE;
#else
  /* Receiving arrived after sending; without it this library refuses,
   * because half a socket is not an offer it makes. */
  return dir == KTLS_TX ? TCP_TXTLS_ENABLE : -1;
#endif
}

#else /* Linux */

bool ktls_initialized(void)
{
  return access("/proc/net/tls_stat", F_OK) == 0;
}

static int ktls_file_names(const char *path, const char *want)
{
  const size_t wlen = strlen(want);
  char buf[4096];
  size_t held = 0;
  int found = 0;

  const int fd = open(path, O_RDONLY);
  if (fd < 0) return 0;
  for (;;) {
    const ssize_t n = read(fd, buf + held, sizeof(buf) - held);
    if (n <= 0) break;
    const size_t have = held + (size_t) n;
    if (have >= wlen) {
      for (size_t i = 0; i <= have - wlen; i++) {
        if (buf[i] == want[0] && memcmp(buf + i, want, wlen) == 0) { found = 1; break; }
      }
    }
    if (found) break;
    held = wlen - 1 < have ? wlen - 1 : have;
    memmove(buf, buf + (have - held), held);
  }
  close(fd);
  return found;
}

bool ktls_available(void)
{
  struct utsname u;
  char path[sizeof(u.release) + 64];

  if (ktls_initialized()) return true;
  if (uname(&u) != 0) return false;
  snprintf(path, sizeof(path), "/lib/modules/%s/modules.dep", u.release);
  if (ktls_file_names(path, "net/tls/tls.ko")) return true;
  snprintf(path, sizeof(path), "/lib/modules/%s/modules.builtin", u.release);
  return ktls_file_names(path, "net/tls/tls.ko") != 0;
}

/* The ULP lookup autoloads the module BEFORE the ULP inspects the
 * socket, and that inspection refuses one that is not ESTABLISHED -
 * so on a dummy socket ENOTCONN is the success sound. */
int ktls_load_module(void)
{
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { ktls_fail("socket"); return -1; }
  const int rc = setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls"));
  const int e = errno;
  close(fd);
  if (rc != 0 && e != ENOTCONN) {
    errno = e;
    ktls_fail("setsockopt(TCP_ULP, \"tls\")");
    return -1;
  }
  return 0;
}

int ktls_attach_ulp(int fd)
{
  if (setsockopt(fd, IPPROTO_TCP, TCP_ULP, "tls", sizeof("tls")) != 0) {
    ktls_fail("setsockopt(TCP_ULP, \"tls\")");
    return -1;
  }
  return 0;
}

int ktls_sol_tls(void) { return SOL_TLS; }
int ktls_optname(ktls_direction dir) { return dir == KTLS_TX ? TLS_TX : TLS_RX; }

#endif

/* ---- the keys this server answers with --------------------------- */

struct ktls_keys {
  SSL_CTX *ctx;
  unsigned char alpn[256];
  size_t alpn_len;
};

/* AES-GCM in software is table-driven and timing-sensitive; with the
 * instructions it is the faster of the two, and it is the ONLY suite a
 * NIC can take over (ethtool tls-hw-tx-offload). ChaCha is
 * constant-time by construction and needs nothing from the machine. */
bool ktls_aes_is_fast(void)
{
#if defined(__x86_64__) || defined(__i386__)
  __builtin_cpu_init();
  return __builtin_cpu_supports("aes") != 0;
#elif defined(__aarch64__)
  return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
  return false;
#endif
}

/* Both suites hash with SHA-256, so the key schedule below needs no
 * second digest. TLS_AES_256_GCM_SHA384 would have brought one, for
 * 14 rounds instead of 10 and no reachable security gain.
 * AES-GCM would work over kTLS too, but its ~388GB-per-key limit has
 * to be counted by whoever writes the bytes - and after the handover
 * that is the kernel, which does not count for us. ChaCha has no
 * practical limit, so nobody has to. */
static SSL_CTX *ktls_ctx_new(void)
{
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  if (ctx == NULL) { ktls_fail("SSL_CTX_new"); return NULL; }
  if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
    ktls_fail("set_proto_version(TLS1.3)");
    SSL_CTX_free(ctx);
    return NULL;
  }
  const char *suites = ktls_aes_is_fast()
                           ? "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
                           : "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
  if (SSL_CTX_set_ciphersuites(ctx, suites) != 1) {
    ktls_fail("set_ciphersuites");
    SSL_CTX_free(ctx);
    return NULL;
  }
  return ctx;
}

static int ktls_pem_into(SSL_CTX *ctx, const char *pem, size_t len, int is_key)
{
  BIO *b = BIO_new_mem_buf(pem, (int) len);
  if (b == NULL) { ktls_fail("BIO_new_mem_buf"); return -1; }
  int ok;
  if (is_key) {
    EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
    ok = k != NULL && SSL_CTX_use_PrivateKey(ctx, k) == 1;
    EVP_PKEY_free(k);
  } else {
    X509 *c = PEM_read_bio_X509(b, NULL, NULL, NULL);
    ok = c != NULL && SSL_CTX_use_certificate(ctx, c) == 1;
    X509_free(c);
  }
  BIO_free(b);
  if (!ok) { ktls_fail(is_key ? "use_PrivateKey" : "use_certificate"); return -1; }
  return 0;
}

/* The server's own ALPN answer: the first name on OUR list that the
 * peer also offered. Order here is preference, not the peer's. */
static int ktls_alpn_pick(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
  const struct ktls_keys *keys = (const struct ktls_keys *) arg;
  (void) ssl;
  for (size_t i = 0; i < keys->alpn_len;) {
    const unsigned char n = keys->alpn[i];
    for (unsigned int j = 0; j < inlen;) {
      if (in[j] == n && memcmp(in + j + 1, keys->alpn + i + 1, n) == 0) {
        *out = in + j + 1;
        *outlen = n;
        return SSL_TLSEXT_ERR_OK;
      }
      j += 1u + in[j];
    }
    i += 1u + n;
  }
  return SSL_TLSEXT_ERR_NOACK;
}

int ktls_keys_set_ciphers(ktls_keys *keys, const char *suites)
{
  if (SSL_CTX_set_ciphersuites(keys->ctx, suites) != 1) {
    ktls_fail("set_ciphersuites");
    return -1;
  }
  return 0;
}

int ktls_keys_set_alpn(ktls_keys *keys, const char *const *protocols, size_t count)
{
  size_t n = 0;
  for (size_t i = 0; i < count; i++) {
    const size_t l = strlen(protocols[i]);
    if (l == 0 || l > 255 || n + 1 + l > sizeof(keys->alpn)) {
      ktls_say("ktls_keys_set_alpn: the protocol names do not fit");
      return -1;
    }
    keys->alpn[n++] = (unsigned char) l;
    memcpy(keys->alpn + n, protocols[i], l);
    n += l;
  }
  keys->alpn_len = n;
  /* Both halves of the same list: set_alpn_protos is what a
   * ClientHello carries, the select callback is what an accepting
   * side answers with. A config is only ever one of the two, and
   * whichever it is not simply never fires. */
  SSL_CTX_set_alpn_select_cb(keys->ctx, ktls_alpn_pick, keys);
  if (SSL_CTX_set_alpn_protos(keys->ctx, keys->alpn, (unsigned) n) != 0) {
    ktls_fail("SSL_CTX_set_alpn_protos");
    return -1;
  }
  return 0;
}

ktls_keys *ktls_keys_server(const char *cert_pem, size_t cert_len,
                            const char *key_pem, size_t key_len)
{
  ktls_keys *keys = (ktls_keys *) calloc(1, sizeof(*keys));
  if (keys == NULL) { ktls_say("out of memory"); return NULL; }
  keys->ctx = ktls_ctx_new();
  if (keys->ctx == NULL) { free(keys); return NULL; }
  if (ktls_pem_into(keys->ctx, cert_pem, cert_len, 0) != 0 ||
      ktls_pem_into(keys->ctx, key_pem, key_len, 1) != 0) {
    SSL_CTX_free(keys->ctx);
    free(keys);
    return NULL;
  }
  return keys;
}

ktls_keys *ktls_keys_client(void)
{
  ktls_keys *keys = (ktls_keys *) calloc(1, sizeof(*keys));
  if (keys == NULL) { ktls_say("out of memory"); return NULL; }
  keys->ctx = ktls_ctx_new();
  if (keys->ctx == NULL) { free(keys); return NULL; }
  SSL_CTX_set_verify(keys->ctx, SSL_VERIFY_NONE, NULL);
  return keys;
}

void ktls_keys_free(ktls_keys *keys)
{
  if (keys == NULL) return;
  SSL_CTX_free(keys->ctx);
  free(keys);
}

/* ---- the exchange ------------------------------------------------ */

/* RFC 8446 5.1: a record is a 5-byte header and its body. Records
 * cross feed() and take() in whatever pieces the caller chose, so the
 * scan carries what a call could not finish. */
struct ktls_records {
  uint64_t offset;        /* bytes seen */
  uint64_t body_left;     /* of the record being walked */
  uint8_t head[5];
  unsigned head_len;
  uint64_t ends[64];      /* cumulative offset just past each record */
  unsigned count;
  bool overflowed;
};

/* The one blob setsockopt takes, in whichever shape the cipher has. */
#if defined(__FreeBSD__)
union ktls_info {
  struct tls_enable en;
};
#else
union ktls_info {
  struct tls_crypto_info head;
  struct tls12_crypto_info_aes_gcm_128 aes;
  struct tls12_crypto_info_chacha20_poly1305 chacha;
};
#endif

struct ktls_exchange {
  SSL *ssl;
  BIO *in;   /* what arrived from the peer */
  BIO *out;  /* what must reach the peer */
  bool done;
  /* A TLS1.3 key change resets the record sequence, so the kernel has
   * to be told how far the application keys have already been used.
   * OpenSSL exposes no accessor for it (its own kTLS reads the record
   * layer directly), so the records are counted where they pass: the
   * NewSessionTickets a server writes right after the handshake, and
   * the request a client may put in the same flight as its Finished. */
  struct ktls_records tx, rx;
  uint64_t tx_at_done, rx_at_done;
  uint64_t rx_fed;
  /* A key update restarts the kernel's sequence at zero, and from
   * there the records are the kernel's to count, not ours. */
  bool rekeyed[2];
  /* RFC 8446 7.1: the two application traffic secrets, caught on
   * their way past. OpenSSL hands them over as SSLKEYLOGFILE lines -
   * the one public door onto the key schedule. */
  unsigned char secret[2][KTLS_SECRET_MAX];
  size_t secret_len[2];
  int cipher;  /* KTLS_AES_GCM_128 or KTLS_CHACHA20_POLY1305 */
  union ktls_info info[2];
  /* RFC 8446 7.3 derives these once. FreeBSD's struct POINTS at them
   * instead of embedding them, so they outlive the call either way. */
  unsigned char key[2][32];
  unsigned char iv[2][12];
};

static void ktls_scan(struct ktls_records *r, const unsigned char *p, size_t n)
{
  while (n > 0) {
    if (r->body_left == 0) {
      const unsigned take = 5u - r->head_len;
      const unsigned got = n < take ? (unsigned) n : take;
      memcpy(r->head + r->head_len, p, got);
      r->head_len += got;
      r->offset += got;
      p += got;
      n -= got;
      if (r->head_len < 5) return;
      r->body_left = ((uint64_t) r->head[3] << 8) | r->head[4];
      r->head_len = 0;
      if (r->body_left == 0) {
        if (r->count < 64) r->ends[r->count++] = r->offset;
        else r->overflowed = true;
      }
      continue;
    }
    const uint64_t got = n < r->body_left ? (uint64_t) n : r->body_left;
    r->body_left -= got;
    r->offset += got;
    p += got;
    n -= (size_t) got;
    if (r->body_left == 0) {
      if (r->count < 64) r->ends[r->count++] = r->offset;
      else r->overflowed = true;
    }
  }
}

/* How many whole records ended in (after, upto]. */
static uint64_t ktls_records_between(const struct ktls_records *r, uint64_t after, uint64_t upto)
{
  uint64_t n = 0;
  for (unsigned i = 0; i < r->count; i++) {
    if (r->ends[i] > after && r->ends[i] <= upto) n++;
  }
  return n;
}

static int ktls_ex_index(void)
{
  static int idx = -1;
  if (idx < 0) idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  return idx;
}

static int ktls_unhex(const char *hex, unsigned char *out, size_t cap, size_t *len)
{
  size_t n = 0;
  while (hex[0] != '\0' && hex[0] != ' ' && hex[0] != '\n') {
    unsigned v = 0;
    if (sscanf(hex, "%2x", &v) != 1) return -1;
    if (n >= cap) return -1;
    out[n++] = (unsigned char) v;
    hex += 2;
  }
  *len = n;
  return 0;
}

/* SSLKEYLOGFILE lines are "<LABEL> <client_random> <secret>"; the two
 * application secrets are the only ones the kernel needs. Which of
 * them is ours to send with depends on which side we are. */
static void ktls_keylog(const SSL *ssl, const char *line)
{
  struct ktls_exchange *x = (struct ktls_exchange *) SSL_get_ex_data(ssl, ktls_ex_index());
  if (x == NULL) return;

  static const char kClient[] = "CLIENT_TRAFFIC_SECRET_0 ";
  static const char kServer[] = "SERVER_TRAFFIC_SECRET_0 ";
  int which;
  const char *rest;
  if (strncmp(line, kClient, sizeof(kClient) - 1) == 0) {
    which = 0;
    rest = line + sizeof(kClient) - 1;
  } else if (strncmp(line, kServer, sizeof(kServer) - 1) == 0) {
    which = 1;
    rest = line + sizeof(kServer) - 1;
  } else {
    return;
  }
  const char *sp = strchr(rest, ' ');
  if (sp == NULL) return;
  (void) ktls_unhex(sp + 1, x->secret[which], KTLS_SECRET_MAX, &x->secret_len[which]);
}

ktls_exchange *ktls_exchange_open(ktls_keys *keys, ktls_role role)
{
  if (keys == NULL) { ktls_say("ktls_exchange_open: no keys"); return NULL; }

  ktls_exchange *x = (ktls_exchange *) calloc(1, sizeof(*x));
  if (x == NULL) { ktls_say("out of memory"); return NULL; }

  x->ssl = SSL_new(keys->ctx);
  x->in = BIO_new(BIO_s_mem());
  x->out = BIO_new(BIO_s_mem());
  if (x->ssl == NULL || x->in == NULL || x->out == NULL) {
    ktls_fail("SSL_new");
    ktls_exchange_free(x);
    return NULL;
  }
  BIO_set_mem_eof_return(x->in, -1);
  /* The socket is never named here. These two are buffers, and the
   * bytes cross through feed/take - so whoever owns the descriptor
   * keeps owning it. */
  SSL_set_bio(x->ssl, x->in, x->out);
  SSL_set_ex_data(x->ssl, ktls_ex_index(), x);
  SSL_CTX_set_keylog_callback(keys->ctx, ktls_keylog);
  if (role == KTLS_SERVER) SSL_set_accept_state(x->ssl);
  else SSL_set_connect_state(x->ssl);
  return x;
}

void ktls_exchange_free(ktls_exchange *x)
{
  if (x == NULL) return;
  if (x->ssl != NULL) SSL_free(x->ssl); /* frees both BIOs */
  else { BIO_free(x->in); BIO_free(x->out); }
  OPENSSL_cleanse(x->secret, sizeof(x->secret));
  OPENSSL_cleanse(x->info, sizeof(x->info));
  free(x);
}

int ktls_exchange_feed(ktls_exchange *x, const void *bytes, size_t len)
{
  if (len == 0) return 0;
  if (BIO_write(x->in, bytes, (int) len) != (int) len) {
    ktls_fail("BIO_write");
    return -1;
  }
  ktls_scan(&x->rx, (const unsigned char *) bytes, len);
  x->rx_fed += len;
  return 0;
}

size_t ktls_exchange_take(ktls_exchange *x, void *out, size_t cap)
{
  const int n = BIO_read(x->out, out, (int) cap);
  if (n <= 0) return 0;
  ktls_scan(&x->tx, (const unsigned char *) out, (size_t) n);
  return (size_t) n;
}

/* RFC 8446 7.3: key = HKDF-Expand-Label(secret, "key", "", 32) and
 * iv = HKDF-Expand-Label(secret, "iv", "", 12). OpenSSL's TLS13-KDF
 * builds the HkdfLabel structure itself, so the only thing spelled
 * here is which label and how many bytes. */
static int ktls_expand(const unsigned char *secret, size_t slen, const char *label,
                       unsigned char *out, size_t olen)
{
  EVP_KDF *kdf = EVP_KDF_fetch(NULL, "TLS13-KDF", NULL);
  if (kdf == NULL) { ktls_fail("EVP_KDF_fetch(TLS13-KDF)"); return -1; }
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (kctx == NULL) { ktls_fail("EVP_KDF_CTX_new"); return -1; }

  int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
  OSSL_PARAM p[6];
  p[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) "SHA256", 0);
  p[1] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
  p[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *) secret, slen);
  p[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, (void *) "tls13 ", 6);
  p[4] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, (void *) label, strlen(label));
  p[5] = OSSL_PARAM_construct_end();

  const int rc = EVP_KDF_derive(kctx, out, olen, p);
  EVP_KDF_CTX_free(kctx);
  if (rc != 1) { ktls_fail("EVP_KDF_derive"); return -1; }
  return 0;
}

static int ktls_fill(struct ktls_exchange *x, int which)
{
  if (x->secret_len[which] == 0) {
    ktls_say("the traffic secret never arrived - is this OpenSSL built with TLS 1.3?");
    return -1;
  }
  const size_t keylen = (x->cipher == KTLS_AES_GCM_128) ? 16 : 32;
  if (ktls_expand(x->secret[which], x->secret_len[which], "key", x->key[which], keylen) != 0 ||
      ktls_expand(x->secret[which], x->secret_len[which], "iv", x->iv[which],
                  sizeof(x->iv[which])) != 0) {
    return -1;
  }

  union ktls_info *ci = &x->info[which];
  memset(ci, 0, sizeof(*ci));
#if defined(__FreeBSD__)
  /* FreeBSD splits nothing: the whole implicit iv goes in with its
   * length, and the struct refers to the exchange's own storage. */
  ci->en.cipher_algorithm =
      (x->cipher == KTLS_AES_GCM_128) ? CRYPTO_AES_NIST_GCM_16 : CRYPTO_CHACHA20_POLY1305;
  ci->en.cipher_key = x->key[which];
  ci->en.cipher_key_len = (int) keylen;
  ci->en.iv = x->iv[which];
  ci->en.iv_len = (int) sizeof(x->iv[which]);
  ci->en.tls_vmajor = TLS_MAJOR_VER_ONE;
  ci->en.tls_vminor = TLS_MINOR_VER_THREE;
#else
  /* RFC 8446 7.3 derives ONE 12-byte implicit iv, and Linux splits it
   * per cipher: AES-GCM takes 4 bytes as salt and 8 as iv, ChaCha has
   * no salt at all and takes all 12. */
  ci->head.version = TLS_1_3_VERSION;
  if (x->cipher == KTLS_AES_GCM_128) {
    ci->head.cipher_type = TLS_CIPHER_AES_GCM_128;
    memcpy(ci->aes.key, x->key[which], sizeof(ci->aes.key));
    memcpy(ci->aes.salt, x->iv[which], sizeof(ci->aes.salt));
    memcpy(ci->aes.iv, x->iv[which] + sizeof(ci->aes.salt), sizeof(ci->aes.iv));
  } else {
    ci->head.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
    memcpy(ci->chacha.key, x->key[which], sizeof(ci->chacha.key));
    memcpy(ci->chacha.iv, x->iv[which], sizeof(ci->chacha.iv));
  }
#endif
  return 0;
}

/* Which of the two the peer and this server settled on. */
static int ktls_negotiated_cipher(SSL *ssl)
{
  const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
  const char *name = c != NULL ? SSL_CIPHER_get_name(c) : NULL;
  if (name == NULL) return 0;
  if (strcmp(name, "TLS_AES_128_GCM_SHA256") == 0) return KTLS_AES_GCM_128;
  if (strcmp(name, "TLS_CHACHA20_POLY1305_SHA256") == 0) return KTLS_CHACHA20_POLY1305;
  return 0;
}

/* Which secret we SEND with is which side we are. */
static int ktls_derive_both(struct ktls_exchange *x)
{
  const int server = SSL_is_server(x->ssl);
  x->cipher = ktls_negotiated_cipher(x->ssl);
  if (x->cipher == 0) {
    ktls_say("the negotiated cipher is not one the kernel is told about here");
    return -1;
  }
  if (ktls_fill(x, server ? 1 : 0) != 0) return -1;  /* ours to write with */
  if (ktls_fill(x, server ? 0 : 1) != 0) return -1;  /* the peer's, to read */
  return 0;
}

int ktls_exchange_step(ktls_exchange *x, ktls_step *step)
{
  if (!x->done) {
    const int rc = SSL_do_handshake(x->ssl);
    if (rc != 1) {
      const int e = SSL_get_error(x->ssl, rc);
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
        ktls_fail("SSL_do_handshake");
        return -1;
      }
      *step = BIO_pending(x->out) > 0 ? KTLS_WRITING : KTLS_READING;
      return 0;
    }
    if (ktls_derive_both(x) != 0) return -1;
    /* Everything written after a side's own Finished is under the
     * application keys, and that is where the kernel's sequence has to
     * continue from. WHERE that boundary sits differs by role: a
     * server's Finished left long ago - the peer had to read it to
     * answer - so everything still pending here is NewSessionTicket,
     * which counts. A client finishes BY writing its Finished, so the
     * record still pending is that one, which does not. */
    x->tx_at_done = x->tx.offset;
    if (!SSL_is_server(x->ssl)) x->tx_at_done += (uint64_t) BIO_pending(x->out);
    x->rx_at_done = x->rx_fed - (uint64_t) BIO_pending(x->in);
    x->done = true;
  }
  /* KTLS_DONE only once nothing is owed. Bytes still sitting here are
   * ciphertext OpenSSL already produced under the handshake keys; the
   * kernel would encrypt them a second time, so the handover may not
   * happen while any are left. */
  *step = BIO_pending(x->out) > 0 ? KTLS_WRITING : KTLS_DONE;
  return 0;
}

const char *ktls_exchange_alpn(const ktls_exchange *x, size_t *len)
{
  const unsigned char *name = NULL;
  unsigned int n = 0;
  SSL_get0_alpn_selected(x->ssl, &name, &n);
  if (name == NULL || n == 0) return NULL;
  *len = n;
  return (const char *) name;
}

/* RFC 8446 4.6.1: a client may put application data in the same
 * flight as its Finished, so records can already be waiting when the
 * exchange finishes. The kernel's stream starts at sequence zero and
 * cannot be handed a backlog, so those records are decrypted here and
 * belong in front of everything the socket delivers afterwards. */
size_t ktls_exchange_backlog(ktls_exchange *x, void *out, size_t cap)
{
  if (!x->done) return 0;
  const int n = SSL_read(x->ssl, out, (int) cap);
  return n > 0 ? (size_t) n : 0;
}

/* The sequence is settled here rather than at the handshake, because
 * both counters are still moving until the last owed byte has left
 * through take() and the backlog has been drained. Call this last. */
const void *ktls_crypto_info(const ktls_exchange *cx, ktls_direction dir, size_t *len)
{
  ktls_exchange *x = (ktls_exchange *) cx;
  if (!x->done) { ktls_say("the exchange has not finished"); return NULL; }
  if (BIO_pending(x->out) > 0) {
    ktls_say("bytes are still owed to the peer - drain ktls_exchange_take first");
    return NULL;
  }
  if (x->tx.overflowed || x->rx.overflowed) {
    ktls_say("too many records before the handover to count the sequence");
    return NULL;
  }

  const int server = SSL_is_server(x->ssl);
  const int which = (dir == KTLS_TX) ? (server ? 1 : 0) : (server ? 0 : 1);
  const uint64_t consumed = x->rx_fed - (uint64_t) BIO_pending(x->in);
  const uint64_t seq = x->rekeyed[which] ? 0
                       : (dir == KTLS_TX)
                           ? ktls_records_between(&x->tx, x->tx_at_done, x->tx.offset)
                           : ktls_records_between(&x->rx, x->rx_at_done, consumed);

  union ktls_info *ci = &x->info[which];
#if defined(__FreeBSD__)
  unsigned char *rec_seq = ci->en.rec_seq;
  *len = sizeof(ci->en);
#else
  unsigned char *rec_seq =
      (x->cipher == KTLS_AES_GCM_128) ? ci->aes.rec_seq : ci->chacha.rec_seq;
  *len = (x->cipher == KTLS_AES_GCM_128) ? sizeof(ci->aes) : sizeof(ci->chacha);
#endif
  for (unsigned i = 0; i < 8; i++) rec_seq[7 - i] = (unsigned char) (seq >> (8 * i));
  return ci;
}

/* How many application records each direction has already spent. The
 * kernel is told to continue from here; a test can check the two
 * sides agree. */
uint64_t ktls_record_sequence(const ktls_exchange *cx, ktls_direction dir)
{
  ktls_exchange *x = (ktls_exchange *) cx;
  if (!x->done) return 0;
  const int server = SSL_is_server(x->ssl);
  const int which = (dir == KTLS_TX) ? (server ? 1 : 0) : (server ? 0 : 1);
  if (x->rekeyed[which]) return 0;
  const uint64_t consumed = x->rx_fed - (uint64_t) BIO_pending(x->in);
  return (dir == KTLS_TX) ? ktls_records_between(&x->tx, x->tx_at_done, x->tx.offset)
                          : ktls_records_between(&x->rx, x->rx_at_done, consumed);
}

/* RFC 8446 7.2: application_traffic_secret_N+1 =
 * HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "",
 * Hash.length). One label, the same expansion the keys came from - so
 * a KeyUpdate needs the 32 bytes of secret this exchange still holds
 * and nothing else. The kernel's sequence restarts at zero, and the
 * caller re-installs the crypto_info for that direction. */
int ktls_next_key(ktls_exchange *x, ktls_direction dir)
{
  if (!x->done) { ktls_say("the exchange has not finished"); return -1; }
  const int server = SSL_is_server(x->ssl);
  const int which = (dir == KTLS_TX) ? (server ? 1 : 0) : (server ? 0 : 1);

  unsigned char next[KTLS_SECRET_MAX];
  const size_t n = x->secret_len[which];
  if (ktls_expand(x->secret[which], n, "traffic upd", next, n) != 0) return -1;
  memcpy(x->secret[which], next, n);
  OPENSSL_cleanse(next, sizeof(next));
  x->rekeyed[which] = true;
  return ktls_fill(x, which);
}

/* AES-GCM may encrypt 2^24.5 records under one key (RFC 8446 5.5);
 * this answers half of that, so a caller has room to act. ChaCha
 * answers 0 - it has no limit anyone will reach. After the handover
 * the kernel writes the records, so the caller bounds them itself:
 * every sendmsg is at least one record and at most ceil(len/16384). */
uint64_t ktls_record_limit(const ktls_exchange *x)
{
  return x->cipher == KTLS_AES_GCM_128 ? (1ULL << 23) : 0;
}

const char *ktls_exchange_cipher(const ktls_exchange *x)
{
  const SSL_CIPHER *c = SSL_get_current_cipher(x->ssl);
  return c != NULL ? SSL_CIPHER_get_name(c) : NULL;
}

/* Reading AND writing, or no TLS at all: a socket the kernel only
 * half owns would put the record layer back in this process for
 * everything coming in, which is the arrangement this library exists
 * to avoid. */
int ktls_offload(const ktls_exchange *x, int fd)
{
  size_t tx_len = 0, rx_len = 0;
  const void *tx = ktls_crypto_info(x, KTLS_TX, &tx_len);
  const void *rx = ktls_crypto_info(x, KTLS_RX, &rx_len);
  if (tx == NULL || rx == NULL) return -1;
  if (!ktls_initialized()) {
    ktls_say("kTLS is not initialized (tls module not loaded) - load it "
             "deliberately: modprobe tls, or ktls_load_module()");
    return -1;
  }
  const int level = ktls_sol_tls();
  const int rx_name = ktls_optname(KTLS_RX);
  if (rx_name < 0) {
    ktls_say("this kernel offloads sending but not receiving, and half a "
             "socket is not an offer this library makes");
    return -1;
  }
  if (ktls_attach_ulp(fd) != 0) return -1;
  if (setsockopt(fd, level, ktls_optname(KTLS_TX), tx, (socklen_t) tx_len) != 0) {
    ktls_fail("setsockopt(TLS_TX)");
    return -1;
  }
  if (setsockopt(fd, level, rx_name, rx, (socklen_t) rx_len) != 0) {
    ktls_fail("setsockopt(TLS_RX)");
    return -1;
  }
  return 0;
}

#else /* neither Linux nor FreeBSD */

static const char kNotHere[] = "kTLS exists on Linux and FreeBSD; this is neither";

const char *ktls_last_error(void) { return kNotHere; }
bool ktls_initialized(void) { return false; }
bool ktls_available(void) { return false; }
int ktls_load_module(void) { return -1; }
int ktls_attach_ulp(int fd) { (void) fd; return -1; }
int ktls_sol_tls(void) { return -1; }
int ktls_optname(ktls_direction dir) { (void) dir; return -1; }
ktls_keys *ktls_keys_server(const char *c, size_t cl, const char *k, size_t kl)
{ (void) c; (void) cl; (void) k; (void) kl; return NULL; }
ktls_keys *ktls_keys_client(void) { return NULL; }
int ktls_keys_set_alpn(ktls_keys *k, const char *const *p, size_t n)
{ (void) k; (void) p; (void) n; return -1; }
void ktls_keys_free(ktls_keys *k) { (void) k; }
ktls_exchange *ktls_exchange_open(ktls_keys *k, ktls_role r) { (void) k; (void) r; return NULL; }
void ktls_exchange_free(ktls_exchange *x) { (void) x; }
int ktls_exchange_feed(ktls_exchange *x, const void *b, size_t l)
{ (void) x; (void) b; (void) l; return -1; }
size_t ktls_exchange_take(ktls_exchange *x, void *o, size_t c) { (void) x; (void) o; (void) c; return 0; }
size_t ktls_exchange_backlog(ktls_exchange *x, void *o, size_t c) { (void) x; (void) o; (void) c; return 0; }
int ktls_exchange_step(ktls_exchange *x, ktls_step *s) { (void) x; (void) s; return -1; }
const char *ktls_exchange_alpn(const ktls_exchange *x, size_t *l) { (void) x; (void) l; return NULL; }
const void *ktls_crypto_info(const ktls_exchange *x, ktls_direction d, size_t *l)
{ (void) x; (void) d; (void) l; return NULL; }
int ktls_offload(const ktls_exchange *x, int fd) { (void) x; (void) fd; return -1; }
uint64_t ktls_record_sequence(const ktls_exchange *x, ktls_direction d) { (void) x; (void) d; return 0; }
bool ktls_aes_is_fast(void) { return false; }
int ktls_keys_set_ciphers(ktls_keys *k, const char *s) { (void) k; (void) s; return -1; }
int ktls_next_key(ktls_exchange *x, ktls_direction d) { (void) x; (void) d; return -1; }
uint64_t ktls_record_limit(const ktls_exchange *x) { (void) x; return 0; }
const char *ktls_exchange_cipher(const ktls_exchange *x) { (void) x; return NULL; }

#endif
