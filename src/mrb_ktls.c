/*
 * mruby-ktls: the boundary between "keys exist" and "the kernel owns
 * the wire". Handshakes live elsewhere, permanently - see README.
 *
 * This first slab carries what needs no key material:
 *   KTLS.supported?  - probe by doing, not by version: a loopback TCP
 *                      pair, TCP_ULP set to "tls" on the connected end
 *   KTLS.ulp(io)     - attach the tls ULP to an ESTABLISHED socket,
 *                      the first step of every kTLS setup
 *
 * TLS_TX/TLS_RX crypto-info installation follows once a consumer with
 * a handshake exists.
 */
#include <mruby.h>
#include <mruby/error.h>

#ifdef __linux__

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOL_TCP
#define SOL_TCP 6
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

/* Fetch the fd from an IO-ish object: Integer passes through, anything
 * else answers #fileno. */
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

/* The probe DOES the thing: a loopback pair, ULP on the connected end.
 * TCP_ULP demands an ESTABLISHED socket, so nothing cheaper answers
 * honestly. Any failure - no CONFIG_TLS, module loading denied, no
 * loopback - reads as "not supported here", which is the question. */
static mrb_value
ktls_supported_p(mrb_state *mrb, mrb_value self)
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
  if (ktls_set_ulp(ktls_fileno(mrb, io)) != 0) {
    mrb_sys_fail(mrb, "setsockopt(TCP_ULP, \"tls\")");
  }
  return io;
}

#else /* !__linux__ */

static mrb_value
ktls_supported_p(mrb_state *mrb, mrb_value self)
{
  return mrb_false_value();
}

static mrb_value
ktls_ulp(mrb_state *mrb, mrb_value self)
{
  mrb_raise(mrb, E_NOTIMP_ERROR, "kTLS is a Linux socket ULP");
  return mrb_nil_value(); /* not reached */
}

#endif

void
mrb_mruby_ktls_gem_init(mrb_state *mrb)
{
  struct RClass *m = mrb_define_module_id(mrb, MRB_SYM(KTLS));
  mrb_define_module_function_id(mrb, m, MRB_SYM_Q(supported), ktls_supported_p,
                                MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, m, MRB_SYM(ulp), ktls_ulp, MRB_ARGS_REQ(1));
}

void
mrb_mruby_ktls_gem_final(mrb_state *mrb)
{
}
