/*
 * mruby-ktls: a TLS handshake that exists only to hand the wire to the
 * kernel. The stack is Amazon's, built to the minimum that carries
 * kTLS: AWS-LC's libcrypto (never its libssl) under s2n-tls, static.
 * After s2n_negotiate the kernel takes the record layer
 * (s2n_connection_ktls_enable_send/recv) and the socket speaks plain
 * send/recv - or io_uring submissions - while s2n leaves the data
 * path.
 *
 * Shaped for a one-thread nonblocking reactor: Connection#negotiate
 * steps (:done / :reading / :writing, never sleeps - self-service
 * blinding), the fd is switched to O_NONBLOCK at attach.
 *
 * KTLS.enabled? / KTLS.ulp need no keys and no s2n; one reads a /proc
 * marker, one attaches the tls ULP directly (see below).
 */
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <s2n.h>
#include <unstable/ktls.h>

#ifndef SOL_TCP
#define SOL_TCP 6
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

/* ---- raw ULP layer (no keys, no s2n) ------------------------------ */

static int
ktls_fileno(mrb_state *mrb, mrb_value io)
{
  if (mrb_integer_p(io)) return (int)mrb_integer(io);
  return (int)mrb_integer(mrb_convert_type(mrb, mrb_funcall_id(mrb, io, MRB_SYM(fileno), 0),
                                           MRB_TT_INTEGER, "Integer", "to_i"));
}

static int
ktls_set_ulp(int fd)
{
  return setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
}

/* Asking must never LOAD: setsockopt(TCP_ULP, "tls") autoloads the
 * tls module, and a capability question has no business changing
 * kernel state. /proc/net/tls_stat exists exactly when tls is
 * initialized - as a module already loaded, or built in - so the
 * passive answer is "usable right now, nothing touched". */
static int
ktls_initialized(void)
{
  return access("/proc/net/tls_stat", F_OK) == 0;
}

static mrb_value
ktls_enabled_p(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(ktls_initialized());
}

/* KTLS.probe - the ONE deliberate loader: does the thing (a loopback
 * pair, ULP on the connected end - TCP_ULP demands an ESTABLISHED
 * socket, nothing cheaper answers honestly) and MAY autoload the tls
 * module doing so. Operators who forbid module loading simply never
 * call it; everything else in this gem stays passive. */
static mrb_value
ktls_probe(mrb_state *mrb, mrb_value self)
{
  mrb_bool ok = FALSE;
  int ls = -1, a = -1, c = -1;
  struct sockaddr_in sa;
  socklen_t slen = sizeof(sa);

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) goto out;
  if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0) goto out;
  if (getsockname(ls, (struct sockaddr *)&sa, &slen) != 0) goto out;
  if (listen(ls, 1) != 0) goto out;
  c = socket(AF_INET, SOCK_STREAM, 0);
  if (c < 0) goto out;
  if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0) goto out;
  a = accept(ls, NULL, NULL);
  if (a < 0) goto out;
  ok = ktls_set_ulp(c) == 0;

out:
  if (a >= 0) close(a);
  if (c >= 0) close(c);
  if (ls >= 0) close(ls);
  return mrb_bool_value(ok);
}

static mrb_value
ktls_ulp(mrb_state *mrb, mrb_value self)
{
  mrb_value io;
  mrb_get_args(mrb, "o", &io);
  if (!ktls_initialized()) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "kTLS is not initialized (tls module not loaded) - load it "
              "deliberately: modprobe tls, or KTLS.probe");
  }
  if (ktls_set_ulp(ktls_fileno(mrb, io)) != 0) {
    mrb_sys_fail(mrb, "setsockopt(TCP_ULP, \"tls\")");
  }
  return io;
}

/* ---- s2n layer ---------------------------------------------------- */

static void
ktls_s2n_raise(mrb_state *mrb, const char *what)
{
  mrb_raisef(mrb, E_RUNTIME_ERROR, "%s: %s", what, s2n_strerror(s2n_errno, "EN"));
}

/* Config: an s2n_config plus the cert chain it holds (s2n stores a
 * reference, not a copy - the chain must outlive the config). */
struct ktls_config {
  struct s2n_config *cfg;
  struct s2n_cert_chain_and_key *chain;
};

static void
ktls_config_free(mrb_state *mrb, void *p)
{
  struct ktls_config *c = (struct ktls_config *)p;
  if (c == NULL) return;
  if (c->cfg != NULL) s2n_config_free(c->cfg);
  if (c->chain != NULL) s2n_cert_chain_and_key_free(c->chain);
  mrb_free(mrb, c);
}

static const struct mrb_data_type ktls_config_type = {"KTLS::Config", ktls_config_free};

/* TLS 1.3 is MANDATORY here: the default policy's minimum is 1.3.
 *
 * The 1.3 kTLS handover exists in s2n only behind
 * s2n_config_ktls_enable_unsafe_tls13 - and that call is the whole
 * KeyUpdate machinery, not its absence: s2n CAN send a KeyUpdate
 * through the offloaded socket (TLS_HANDSHAKE cmsg, re-derive,
 * re-setsockopt TLS_TX) and process a received one (re-setsockopt
 * TLS_RX). "unsafe" labels three caveats, all about raw-fd use, and
 * THIS LAYER'S EMBEDDER OWNS THEM NOW - decided knowingly:
 *
 *   1. The AES-GCM encryption limit (2^24.5 full records ~ 388GB per
 *      direction per key) is only accounted for traffic through
 *      s2n_send. Raw fd writes escape the count: the embedder caps
 *      bytes per connection below the limit (or prefers
 *      CHACHA20-POLY1305, which has no practical one) - see
 *      Connection#cipher.
 *   2. An incoming KeyUpdate surfaces on a raw read() as EIO, not as
 *      data. The embedder treats that as the end of the connection
 *      (errors kill the connection, never the process).
 *   3. Re-keying via a second setsockopt needs kernel >= 6.14.
 */
static void
ktls_config_common(mrb_state *mrb, struct ktls_config *c)
{
  c->cfg = s2n_config_new_minimal();
  if (c->cfg == NULL) ktls_s2n_raise(mrb, "s2n_config_new_minimal");
  if (s2n_config_set_cipher_preferences(c->cfg, "AWS-CRT-SDK-TLSv1.3") != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "set_cipher_preferences");
  }
  if (s2n_config_ktls_enable_unsafe_tls13(c->cfg) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "ktls_enable_unsafe_tls13");
  }
}

/* KTLS::Config.server(cert_pem, key_pem) */
static mrb_value
ktls_config_server(mrb_state *mrb, mrb_value klass)
{
  char *cert, *key;
  mrb_int certlen, keylen;
  mrb_get_args(mrb, "ss", &cert, &certlen, &key, &keylen);

  struct ktls_config *c = (struct ktls_config *)mrb_calloc(mrb, 1, sizeof(*c));
  struct RData *data =
      mrb_data_object_alloc(mrb, mrb_class_ptr(klass), c, &ktls_config_type);

  ktls_config_common(mrb, c);
  c->chain = s2n_cert_chain_and_key_new();
  if (c->chain == NULL) ktls_s2n_raise(mrb, "s2n_cert_chain_and_key_new");
  if (s2n_cert_chain_and_key_load_pem_bytes(c->chain, (uint8_t *)cert, (uint32_t)certlen,
                                            (uint8_t *)key, (uint32_t)keylen) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "load_pem");
  }
  if (s2n_config_add_cert_chain_and_key_to_store(c->cfg, c->chain) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "add_cert_chain");
  }
  return mrb_obj_value(data);
}

/* KTLS::Config.client - for now trust is DISABLED (loopback tests,
 * pinned deployments do their own checks). Verification arrives with
 * a trust-store API, named here so nobody mistakes this for one. */
static mrb_value
ktls_config_client(mrb_state *mrb, mrb_value klass)
{
  struct ktls_config *c = (struct ktls_config *)mrb_calloc(mrb, 1, sizeof(*c));
  struct RData *data =
      mrb_data_object_alloc(mrb, mrb_class_ptr(klass), c, &ktls_config_type);
  ktls_config_common(mrb, c);
  if (s2n_config_disable_x509_verification(c->cfg) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "disable_x509_verification");
  }
  return mrb_obj_value(data);
}

/* config.policy = "..." - an s2n security-policy name, overriding the
 * default. The default REQUIRES TLS 1.3 (AWS-CRT-SDK-TLSv1.3); pick a
 * weaker lane only knowing why. */
static mrb_value
ktls_config_policy_set(mrb_state *mrb, mrb_value self)
{
  const char *name;
  mrb_get_args(mrb, "z", &name);
  struct ktls_config *c = (struct ktls_config *)mrb_data_get_ptr(mrb, self, &ktls_config_type);
  if (s2n_config_set_cipher_preferences(c->cfg, name) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "set_cipher_preferences");
  }
  return self;
}

/* Connection */

struct ktls_conn {
  struct s2n_connection *conn;
};

static void
ktls_conn_free(mrb_state *mrb, void *p)
{
  struct ktls_conn *c = (struct ktls_conn *)p;
  if (c == NULL) return;
  if (c->conn != NULL) s2n_connection_free(c->conn);
  mrb_free(mrb, c);
}

static const struct mrb_data_type ktls_conn_type = {"KTLS::Connection", ktls_conn_free};

/* KTLS::Connection.new(config, io, :server | :client). The fd goes
 * O_NONBLOCK here: this API is shaped for a reactor, negotiate steps
 * and never sleeps (self-service blinding for the same reason). */
static mrb_value
ktls_conn_init(mrb_state *mrb, mrb_value self)
{
  mrb_value cfgv, io;
  mrb_sym mode;
  mrb_get_args(mrb, "oon", &cfgv, &io, &mode);
  struct ktls_config *cfg =
      (struct ktls_config *)mrb_data_get_ptr(mrb, cfgv, &ktls_config_type);

  s2n_mode m;
  if (mode == MRB_SYM(server)) m = S2N_SERVER;
  else if (mode == MRB_SYM(client)) m = S2N_CLIENT;
  else mrb_raise(mrb, E_ARGUMENT_ERROR, "mode must be :server or :client");

  struct ktls_conn *c = (struct ktls_conn *)mrb_calloc(mrb, 1, sizeof(*c));
  mrb_data_init(self, c, &ktls_conn_type);

  c->conn = s2n_connection_new(m);
  if (c->conn == NULL) ktls_s2n_raise(mrb, "s2n_connection_new");
  if (s2n_connection_set_config(c->conn, cfg->cfg) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "set_config");
  }
  if (s2n_connection_set_blinding(c->conn, S2N_SELF_SERVICE_BLINDING) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "set_blinding");
  }
  const int fd = ktls_fileno(mrb, io);
  const int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) mrb_sys_fail(mrb, "O_NONBLOCK");
  /* Nagle holds the second of s2n's CCS+Finished writes hostage to a
   * delayed ACK - found as a live stall: a nonblocking stepper spins
   * its budget away in microseconds while 58 bytes sit in the kernel
   * for 40ms. Handshake messages are latency traffic; NODELAY is the
   * correct posture and best-effort (non-TCP fds refuse, fine). */
  const int one = 1;
  (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  if (s2n_connection_set_fd(c->conn, fd) != S2N_SUCCESS) ktls_s2n_raise(mrb, "set_fd");
  /* The config must outlive the connection; s2n holds a pointer. */
  mrb_iv_set(mrb, self, MRB_IVSYM(config), cfgv);
  return self;
}

static mrb_value
ktls_blocked_sym(mrb_state *mrb, s2n_blocked_status blocked)
{
  switch (blocked) {
    case S2N_NOT_BLOCKED: return mrb_symbol_value(MRB_SYM(done));
    case S2N_BLOCKED_ON_READ: return mrb_symbol_value(MRB_SYM(reading));
    case S2N_BLOCKED_ON_WRITE: return mrb_symbol_value(MRB_SYM(writing));
    default: return mrb_symbol_value(MRB_SYM(blocked));
  }
}

/* conn.negotiate -> :done | :reading | :writing. Call again when the
 * fd is ready in the named direction; raises on real failure. */
static mrb_value
ktls_conn_negotiate(mrb_state *mrb, mrb_value self)
{
  struct ktls_conn *c = (struct ktls_conn *)mrb_data_get_ptr(mrb, self, &ktls_conn_type);
  s2n_blocked_status blocked = S2N_NOT_BLOCKED;
  if (s2n_negotiate(c->conn, &blocked) != S2N_SUCCESS) {
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
      ktls_s2n_raise(mrb, "s2n_negotiate");
    }
  }
  return ktls_blocked_sym(mrb, blocked);
}

/* conn.version -> :tls13 (or what else was negotiated). */
static mrb_value
ktls_conn_version(mrb_state *mrb, mrb_value self)
{
  struct ktls_conn *c = (struct ktls_conn *)mrb_data_get_ptr(mrb, self, &ktls_conn_type);
  switch (s2n_connection_get_actual_protocol_version(c->conn)) {
    case S2N_TLS13: return mrb_symbol_value(MRB_SYM(tls13));
    case S2N_TLS12: return mrb_symbol_value(MRB_SYM(tls12));
    case S2N_TLS11: return mrb_symbol_value(MRB_SYM(tls11));
    case S2N_TLS10: return mrb_symbol_value(MRB_SYM(tls10));
    default: return mrb_nil_value();
  }
}

/* conn.shutdown -> :done | :reading | :writing. Steps a clean TLS
 * shutdown (close_notify both ways, RFC 8446 6.1); call again when
 * the fd is ready. KTLS::Socket#close drives it best-effort. */
static mrb_value
ktls_conn_shutdown(mrb_state *mrb, mrb_value self)
{
  struct ktls_conn *c = (struct ktls_conn *)mrb_data_get_ptr(mrb, self, &ktls_conn_type);
  s2n_blocked_status blocked = S2N_NOT_BLOCKED;
  if (s2n_shutdown(c->conn, &blocked) != S2N_SUCCESS) {
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
      ktls_s2n_raise(mrb, "s2n_shutdown");
    }
  }
  return ktls_blocked_sym(mrb, blocked);
}

/* KTLS.dup_fd(fd) -> Integer. KTLS::Socket.attach adopts a COPY of
 * the caller's fd (dup), so both objects own their descriptor and
 * either may close without killing the other. */
static mrb_value
ktls_dup_fd(mrb_state *mrb, mrb_value self)
{
  mrb_int fd;
  mrb_get_args(mrb, "i", &fd);
  const int nfd = dup((int)fd);
  if (nfd < 0) mrb_sys_fail(mrb, "dup");
  return mrb_fixnum_value(nfd);
}

/* conn.cipher -> the negotiated cipher's IANA name. The caller needs
 * it to know which encryption limit applies to raw-fd sends after the
 * handover: AES-GCM ~388GB per direction per key, CHACHA20-POLY1305
 * practically none. */
static mrb_value
ktls_conn_cipher(mrb_state *mrb, mrb_value self)
{
  struct ktls_conn *c = (struct ktls_conn *)mrb_data_get_ptr(mrb, self, &ktls_conn_type);
  const char *name = s2n_connection_get_cipher(c->conn);
  if (name == NULL) return mrb_nil_value();
  return mrb_str_new_cstr(mrb, name);
}

/* conn.enable_ktls_send / conn.enable_ktls_recv - the handover. After both, the
 * fd's plain send/recv are TLS and s2n is out of the data path. */
static void
ktls_require_initialized(mrb_state *mrb)
{
  if (!ktls_initialized()) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "kTLS is not initialized (tls module not loaded) - load it "
              "deliberately: modprobe tls, or KTLS.probe");
  }
}

static mrb_value
ktls_conn_ktls_send(mrb_state *mrb, mrb_value self)
{
  struct ktls_conn *c = (struct ktls_conn *)mrb_data_get_ptr(mrb, self, &ktls_conn_type);
  ktls_require_initialized(mrb);
  if (s2n_connection_ktls_enable_send(c->conn) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "ktls_enable_send");
  }
  return self;
}

static mrb_value
ktls_conn_ktls_recv(mrb_state *mrb, mrb_value self)
{
  struct ktls_conn *c = (struct ktls_conn *)mrb_data_get_ptr(mrb, self, &ktls_conn_type);
  ktls_require_initialized(mrb);
  if (s2n_connection_ktls_enable_recv(c->conn) != S2N_SUCCESS) {
    ktls_s2n_raise(mrb, "ktls_enable_recv");
  }
  return self;
}

/* Pre-handover I/O through s2n, for the tiers (and tests) that speak
 * before or without kTLS. Returns [bytes_or_string, status]. */
static mrb_value
ktls_conn_send(mrb_state *mrb, mrb_value self)
{
  char *buf;
  mrb_int len;
  mrb_get_args(mrb, "s", &buf, &len);
  struct ktls_conn *c = (struct ktls_conn *)mrb_data_get_ptr(mrb, self, &ktls_conn_type);
  s2n_blocked_status blocked = S2N_NOT_BLOCKED;
  const ssize_t n = s2n_send(c->conn, buf, (ssize_t)len, &blocked);
  if (n < 0 && s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
    ktls_s2n_raise(mrb, "s2n_send");
  }
  mrb_value pair = mrb_ary_new_capa(mrb, 2);
  mrb_ary_push(mrb, pair, mrb_fixnum_value(n < 0 ? 0 : n));
  mrb_ary_push(mrb, pair, ktls_blocked_sym(mrb, blocked));
  return pair;
}

static mrb_value
ktls_conn_recv(mrb_state *mrb, mrb_value self)
{
  mrb_int len;
  mrb_get_args(mrb, "i", &len);
  if (len <= 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "length must be positive");
  struct ktls_conn *c = (struct ktls_conn *)mrb_data_get_ptr(mrb, self, &ktls_conn_type);
  mrb_value out = mrb_str_new(mrb, NULL, len);
  s2n_blocked_status blocked = S2N_NOT_BLOCKED;
  const ssize_t n = s2n_recv(c->conn, RSTRING_PTR(out), (ssize_t)len, &blocked);
  if (n < 0 && s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
    ktls_s2n_raise(mrb, "s2n_recv");
  }
  mrb_str_resize(mrb, out, n < 0 ? 0 : n);
  mrb_value pair = mrb_ary_new_capa(mrb, 2);
  mrb_ary_push(mrb, pair, out);
  mrb_ary_push(mrb, pair, ktls_blocked_sym(mrb, blocked));
  return pair;
}

void
mrb_mruby_ktls_gem_init(mrb_state *mrb)
{
  /* Process-wide, once; s2n refuses double init and cleanup belongs
   * to process exit (multiple mrb_states share the library state). */
  static int s2n_ready = 0;
  if (!s2n_ready) {
    if (s2n_init() != S2N_SUCCESS) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "s2n_init: %s", s2n_strerror(s2n_errno, "EN"));
    }
    s2n_ready = 1;
  }

  struct RClass *m = mrb_define_module_id(mrb, MRB_SYM(KTLS));
  mrb_define_module_function_id(mrb, m, MRB_SYM_Q(enabled), ktls_enabled_p,
                                MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM(probe), ktls_probe, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM(ulp), ktls_ulp, MRB_ARGS_REQ(1));
  mrb_define_module_function_id(mrb, m, MRB_SYM(dup_fd), ktls_dup_fd, MRB_ARGS_REQ(1));

  struct RClass *cfg = mrb_define_class_under_id(mrb, m, MRB_SYM(Config), mrb->object_class);
  MRB_SET_INSTANCE_TT(cfg, MRB_TT_DATA);
  mrb_undef_class_method_id(mrb, cfg, MRB_SYM(new));
  mrb_define_class_method_id(mrb, cfg, MRB_SYM(server), ktls_config_server, MRB_ARGS_REQ(2));
  mrb_define_class_method_id(mrb, cfg, MRB_SYM(client), ktls_config_client, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, cfg, MRB_SYM_E(policy), ktls_config_policy_set, MRB_ARGS_REQ(1));

  struct RClass *cn =
      mrb_define_class_under_id(mrb, m, MRB_SYM(Connection), mrb->object_class);
  MRB_SET_INSTANCE_TT(cn, MRB_TT_DATA);
  mrb_define_method_id(mrb, cn, MRB_SYM(initialize), ktls_conn_init, MRB_ARGS_REQ(3));
  mrb_define_method_id(mrb, cn, MRB_SYM(negotiate), ktls_conn_negotiate, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, cn, MRB_SYM(version), ktls_conn_version, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, cn, MRB_SYM(cipher), ktls_conn_cipher, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, cn, MRB_SYM(shutdown), ktls_conn_shutdown, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, cn, MRB_SYM(enable_ktls_send), ktls_conn_ktls_send, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, cn, MRB_SYM(enable_ktls_recv), ktls_conn_ktls_recv, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, cn, MRB_SYM(send), ktls_conn_send, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, cn, MRB_SYM(recv), ktls_conn_recv, MRB_ARGS_REQ(1));
}

void
mrb_mruby_ktls_gem_final(mrb_state *mrb)
{
}

#else /* !__linux__ */

static mrb_value
ktls_enabled_p(mrb_state *mrb, mrb_value self)
{
  return mrb_false_value();
}

static mrb_value
ktls_notimp(mrb_state *mrb, mrb_value self)
{
  mrb_raise(mrb, E_NOTIMP_ERROR, "kTLS is a Linux socket ULP");
  return mrb_nil_value(); /* not reached */
}

void
mrb_mruby_ktls_gem_init(mrb_state *mrb)
{
  struct RClass *m = mrb_define_module_id(mrb, MRB_SYM(KTLS));
  mrb_define_module_function_id(mrb, m, MRB_SYM_Q(enabled), ktls_enabled_p,
                                MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM(probe), ktls_notimp, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM(ulp), ktls_notimp, MRB_ARGS_REQ(1));
}

void
mrb_mruby_ktls_gem_final(mrb_state *mrb)
{
}

#endif
