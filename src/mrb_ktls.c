/*
 * The Ruby surface, one call deep over include/ktls.h - the same
 * functions C and C++ callers use. Nothing about the exchange lives
 * here: no socket, no record layer, no key material that ktls.c does
 * not already own.
 */
#include "ktls.h"

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <string.h>

static struct RClass *ktls_error_class(mrb_state *mrb)
{
  return mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(KTLS)), MRB_SYM(Error));
}

static void ktls_raise(mrb_state *mrb)
{
  mrb_raise(mrb, ktls_error_class(mrb), ktls_last_error());
}

/* ---- KTLS::Keys --------------------------------------------------- */

static void keys_free(mrb_state *mrb, void *p)
{
  (void) mrb;
  ktls_keys_free((ktls_keys *) p);
}

static const struct mrb_data_type keys_type = { "KTLS::Keys", keys_free };

static ktls_keys *keys_of(mrb_state *mrb, mrb_value self)
{
  return (ktls_keys *) mrb_data_get_ptr(mrb, self, &keys_type);
}

/* KTLS::Keys.server(cert_pem, key_pem) */
static mrb_value keys_server(mrb_state *mrb, mrb_value klass)
{
  char *cert, *key;
  mrb_int certlen, keylen;
  mrb_get_args(mrb, "ss", &cert, &certlen, &key, &keylen);

  ktls_keys *k = ktls_keys_server(cert, (size_t) certlen, key, (size_t) keylen);
  if (k == NULL) ktls_raise(mrb);
  return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(klass), k, &keys_type));
}

/* KTLS::Keys.client - no trust store, for loopback tests and pinned
 * deployments that verify themselves. */
static mrb_value keys_client(mrb_state *mrb, mrb_value klass)
{
  ktls_keys *k = ktls_keys_client();
  if (k == NULL) ktls_raise(mrb);
  return mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(klass), k, &keys_type));
}

/* keys.alpn = ["h2", "http/1.1"] - order is preference. */
static mrb_value keys_alpn_set(mrb_state *mrb, mrb_value self)
{
  mrb_value list;
  mrb_get_args(mrb, "A", &list);

  const mrb_int n = RARRAY_LEN(list);
  if (n <= 0 || n > 8) mrb_raise(mrb, E_ARGUMENT_ERROR, "one to eight protocol names");
  const char *names[8];
  for (mrb_int i = 0; i < n; i++) {
    names[i] = mrb_string_cstr(mrb, mrb_ary_entry(list, i));
  }
  if (ktls_keys_set_alpn(keys_of(mrb, self), names, (size_t) n) != 0) ktls_raise(mrb);
  return list;
}

/* keys.ciphers = "TLS_AES_128_GCM_SHA256:..." - overrides the order
 * this machine would have chosen. */
static mrb_value keys_ciphers_set(mrb_state *mrb, mrb_value self)
{
  const char *suites;
  mrb_get_args(mrb, "z", &suites);
  if (ktls_keys_set_ciphers(keys_of(mrb, self), suites) != 0) ktls_raise(mrb);
  return mrb_str_new_cstr(mrb, suites);
}

/* ---- KTLS::Exchange ----------------------------------------------- */

static void exchange_free(mrb_state *mrb, void *p)
{
  (void) mrb;
  ktls_exchange_free((ktls_exchange *) p);
}

static const struct mrb_data_type exchange_type = { "KTLS::Exchange", exchange_free };

static ktls_exchange *exchange_of(mrb_state *mrb, mrb_value self)
{
  return (ktls_exchange *) mrb_data_get_ptr(mrb, self, &exchange_type);
}

static ktls_direction direction_of(mrb_state *mrb, mrb_sym d)
{
  if (d == MRB_SYM(tx)) return KTLS_TX;
  if (d == MRB_SYM(rx)) return KTLS_RX;
  mrb_raise(mrb, E_ARGUMENT_ERROR, "direction must be :tx or :rx");
  return KTLS_TX; /* not reached */
}

/* KTLS::Exchange.new(keys, :server | :client). No descriptor: the
 * bytes cross through #feed and #take, so the socket stays whoever's
 * it was. */
static mrb_value exchange_init(mrb_state *mrb, mrb_value self)
{
  mrb_value keysv;
  mrb_sym role;
  mrb_get_args(mrb, "on", &keysv, &role);

  ktls_role r;
  if (role == MRB_SYM(server)) r = KTLS_SERVER;
  else if (role == MRB_SYM(client)) r = KTLS_CLIENT;
  else mrb_raise(mrb, E_ARGUMENT_ERROR, "role must be :server or :client");

  ktls_exchange *x = ktls_exchange_open(keys_of(mrb, keysv), r);
  if (x == NULL) ktls_raise(mrb);
  mrb_data_init(self, x, &exchange_type);
  /* The keys must outlive the exchange; the C side holds a pointer. */
  mrb_iv_set(mrb, self, MRB_IVSYM(keys), keysv);
  return self;
}

static mrb_value exchange_feed(mrb_state *mrb, mrb_value self)
{
  char *bytes;
  mrb_int len;
  mrb_get_args(mrb, "s", &bytes, &len);
  if (ktls_exchange_feed(exchange_of(mrb, self), bytes, (size_t) len) != 0) ktls_raise(mrb);
  return mrb_fixnum_value(len);
}

/* Everything owed to the peer, as one String. "" when nothing is. */
static mrb_value exchange_take(mrb_state *mrb, mrb_value self)
{
  ktls_exchange *x = exchange_of(mrb, self);
  mrb_value out = mrb_str_new(mrb, NULL, 0);
  char buf[16384];
  for (;;) {
    const size_t n = ktls_exchange_take(x, buf, sizeof(buf));
    if (n == 0) break;
    out = mrb_str_cat(mrb, out, buf, n);
  }
  return out;
}

/* :done | :reading | :writing */
static mrb_value exchange_step(mrb_state *mrb, mrb_value self)
{
  ktls_step step = KTLS_READING;
  if (ktls_exchange_step(exchange_of(mrb, self), &step) != 0) ktls_raise(mrb);
  switch (step) {
    case KTLS_DONE: return mrb_symbol_value(MRB_SYM(done));
    case KTLS_WRITING: return mrb_symbol_value(MRB_SYM(writing));
    default: return mrb_symbol_value(MRB_SYM(reading));
  }
}

/* Application bytes that arrived in the same flight as the peer's
 * Finished, and - on either side - the post-handshake records that
 * have to be consumed before the record sequence is read. */
static mrb_value exchange_backlog(mrb_state *mrb, mrb_value self)
{
  ktls_exchange *x = exchange_of(mrb, self);
  mrb_value out = mrb_str_new(mrb, NULL, 0);
  char buf[16384];
  for (;;) {
    const size_t n = ktls_exchange_backlog(x, buf, sizeof(buf));
    if (n == 0) break;
    out = mrb_str_cat(mrb, out, buf, n);
  }
  return out;
}

static mrb_value exchange_alpn(mrb_state *mrb, mrb_value self)
{
  size_t len = 0;
  const char *name = ktls_exchange_alpn(exchange_of(mrb, self), &len);
  return name == NULL ? mrb_nil_value() : mrb_str_new(mrb, name, len);
}

static mrb_value exchange_cipher(mrb_state *mrb, mrb_value self)
{
  const char *name = ktls_exchange_cipher(exchange_of(mrb, self));
  return name == NULL ? mrb_nil_value() : mrb_str_new_cstr(mrb, name);
}

/* The setsockopt payload for one direction, as a String - so a caller
 * that submits its own setsockopt (over io_uring, against a direct
 * descriptor) has the exact bytes. Read it LAST. */
static mrb_value exchange_crypto_info(mrb_state *mrb, mrb_value self)
{
  mrb_sym dir;
  mrb_get_args(mrb, "n", &dir);
  size_t len = 0;
  const void *info = ktls_crypto_info(exchange_of(mrb, self), direction_of(mrb, dir), &len);
  if (info == NULL) ktls_raise(mrb);
  return mrb_str_new(mrb, (const char *) info, len);
}

static mrb_value exchange_record_sequence(mrb_state *mrb, mrb_value self)
{
  mrb_sym dir;
  mrb_get_args(mrb, "n", &dir);
  return mrb_int_value(
      mrb, (mrb_int) ktls_record_sequence(exchange_of(mrb, self), direction_of(mrb, dir)));
}

static mrb_value exchange_record_limit(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, (mrb_int) ktls_record_limit(exchange_of(mrb, self)));
}

/* RFC 8446 4.6.3: turn the secret one notch. The kernel's sequence
 * restarts at zero and the caller re-installs the crypto_info. */
static mrb_value exchange_next_key(mrb_state *mrb, mrb_value self)
{
  mrb_sym dir;
  mrb_get_args(mrb, "n", &dir);
  if (ktls_next_key(exchange_of(mrb, self), direction_of(mrb, dir)) != 0) ktls_raise(mrb);
  return self;
}

/* ULP plus both directions on a descriptor this process holds. */
static mrb_value exchange_offload(mrb_state *mrb, mrb_value self)
{
  mrb_value io;
  mrb_get_args(mrb, "o", &io);
  const mrb_int fd =
      mrb_integer(mrb_type_convert(mrb, io, MRB_TT_INTEGER, MRB_SYM(fileno)));
  if (ktls_offload(exchange_of(mrb, self), (int) fd) != 0) ktls_raise(mrb);
  return self;
}

/* ---- the module -------------------------------------------------- */

static mrb_value m_initialized(mrb_state *mrb, mrb_value self)
{
  (void) mrb; (void) self;
  return mrb_bool_value(ktls_initialized());
}

static mrb_value m_available(mrb_state *mrb, mrb_value self)
{
  (void) mrb; (void) self;
  return mrb_bool_value(ktls_available());
}

static mrb_value m_aes_fast(mrb_state *mrb, mrb_value self)
{
  (void) mrb; (void) self;
  return mrb_bool_value(ktls_aes_is_fast());
}

static mrb_value m_load_module(mrb_state *mrb, mrb_value self)
{
  (void) self;
  if (ktls_load_module() != 0) ktls_raise(mrb);
  return mrb_true_value();
}

static mrb_value m_attach_ulp(mrb_state *mrb, mrb_value self)
{
  (void) self;
  mrb_value io;
  mrb_get_args(mrb, "o", &io);
  const mrb_int fd =
      mrb_integer(mrb_type_convert(mrb, io, MRB_TT_INTEGER, MRB_SYM(fileno)));
  if (ktls_attach_ulp((int) fd) != 0) ktls_raise(mrb);
  return io;
}

void mrb_mruby_ktls_gem_init(mrb_state *mrb)
{
  struct RClass *m = mrb_define_module_id(mrb, MRB_SYM(KTLS));
  mrb_define_class_under_id(mrb, m, MRB_SYM(Error), mrb->eStandardError_class);

  mrb_define_module_function_id(mrb, m, MRB_SYM_Q(initialized), m_initialized, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM_Q(available), m_available, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM_Q(aes_fast), m_aes_fast, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM(load_module), m_load_module, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM(attach_ulp), m_attach_ulp, MRB_ARGS_REQ(1));

  /* The socket option level and names, so a caller can submit the
   * setsockopt itself instead of going through #offload. */
  mrb_define_const_id(mrb, m, MRB_SYM(SOL_TLS), mrb_fixnum_value(ktls_sol_tls()));
  mrb_define_const_id(mrb, m, MRB_SYM(TLS_TX), mrb_fixnum_value(ktls_optname(KTLS_TX)));
  mrb_define_const_id(mrb, m, MRB_SYM(TLS_RX), mrb_fixnum_value(ktls_optname(KTLS_RX)));

  struct RClass *keys = mrb_define_class_under_id(mrb, m, MRB_SYM(Keys), mrb->object_class);
  MRB_SET_INSTANCE_TT(keys, MRB_TT_DATA);
  mrb_undef_class_method_id(mrb, keys, MRB_SYM(new));
  mrb_define_class_method_id(mrb, keys, MRB_SYM(server), keys_server, MRB_ARGS_REQ(2));
  mrb_define_class_method_id(mrb, keys, MRB_SYM(client), keys_client, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, keys, MRB_SYM_E(alpn), keys_alpn_set, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, keys, MRB_SYM_E(ciphers), keys_ciphers_set, MRB_ARGS_REQ(1));

  struct RClass *x = mrb_define_class_under_id(mrb, m, MRB_SYM(Exchange), mrb->object_class);
  MRB_SET_INSTANCE_TT(x, MRB_TT_DATA);
  mrb_define_method_id(mrb, x, MRB_SYM(initialize), exchange_init, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, x, MRB_SYM(feed), exchange_feed, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, x, MRB_SYM(take), exchange_take, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, x, MRB_SYM(step), exchange_step, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, x, MRB_SYM(backlog), exchange_backlog, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, x, MRB_SYM(alpn), exchange_alpn, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, x, MRB_SYM(cipher), exchange_cipher, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, x, MRB_SYM(crypto_info), exchange_crypto_info, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, x, MRB_SYM(record_sequence), exchange_record_sequence,
                       MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, x, MRB_SYM(record_limit), exchange_record_limit, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, x, MRB_SYM(next_key), exchange_next_key, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, x, MRB_SYM(offload), exchange_offload, MRB_ARGS_REQ(1));
}

void mrb_mruby_ktls_gem_final(mrb_state *mrb)
{
  (void) mrb;
}
