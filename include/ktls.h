/*
 * ktls.h - agree keys, hand them to the kernel, get out of the way.
 *
 * This library never touches the socket. It is fed the bytes that
 * arrived and hands back the bytes that must go out, so whoever owns
 * the descriptor keeps owning it - io_uring submissions against a
 * direct descriptor included. When the exchange is done it produces
 * the two crypto_info blobs the kernel wants, and from the setsockopt
 * that carries them the KERNEL is the record layer: plain send/recv
 * are TLS, and this library has nothing left to do.
 *
 * TLS 1.3 only, and two suites that both hash with SHA-256:
 * TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256. AES first
 * where the machine has the instructions - it is also the only one a
 * NIC can take over - ChaCha first otherwise, where table-driven AES
 * would be both slower and timing-sensitive.
 *
 * Backed by OpenSSL, which appears nowhere in this header: the types
 * are opaque, so a C or C++ embedder needs this file and nothing
 * else. The mruby binding in src/mrb_ktls.c is one more caller.
 */
#ifndef KTLS_H
#define KTLS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The last failure on this thread, as a sentence. Valid until the
 * next failing call on this thread. */
const char *ktls_last_error(void);

/* ---- what the kernel can do, asked without changing it ----------- */

/* Is the tls subsystem initialized right now - module loaded, or
 * built in? Reads the /proc/net/tls_stat marker, so asking never
 * changes the answer. */
bool ktls_initialized(void);

/* Does THIS kernel ship it, loaded or not? initialized counts, else
 * the running kernel's module index must list net/tls/tls.ko. False
 * means ktls_load_module cannot help. */
bool ktls_available(void);

/* The ONE deliberate loader: one setsockopt on a dummy socket, whose
 * ULP lookup autoloads the module. 0, or -1 with errno set.
 * Everything else here refuses by name rather than loading for you. */
int ktls_load_module(void);

/* ---- the keys this server answers with --------------------------- */

/* Cert chain, private key, and the one cipher suite. One per
 * listener, shared by every exchange on it, and it must outlive
 * them. NULL on failure. */
typedef struct ktls_keys ktls_keys;

ktls_keys *ktls_keys_server(const char *cert_pem, size_t cert_len,
                            const char *key_pem, size_t key_len);

/* Does this machine have the AES instructions? The default suite order
 * follows this answer; ktls_keys_set_ciphers overrides it with an
 * OpenSSL TLS 1.3 ciphersuite list. */
bool ktls_aes_is_fast(void);
int ktls_keys_set_ciphers(ktls_keys *keys, const char *suites);

/* Peer verification is DISABLED - for loopback tests and pinned
 * deployments that verify themselves. Not a trust store. */
ktls_keys *ktls_keys_client(void);

/* The ALPN protocols this server offers, most preferred first, as
 * wire-format names ("h2", "http/1.1"). Without this no ALPN
 * extension is answered at all. */
int ktls_keys_set_alpn(ktls_keys *keys, const char *const *protocols, size_t count);

void ktls_keys_free(ktls_keys *keys);

/* ---- the exchange ------------------------------------------------ */

typedef struct ktls_exchange ktls_exchange;

typedef enum { KTLS_SERVER = 0, KTLS_CLIENT = 1 } ktls_role;

/* What the exchange is waiting for. KTLS_WRITING means bytes are
 * waiting in ktls_exchange_take that the peer has not been sent yet. */
typedef enum { KTLS_DONE = 0, KTLS_READING = 1, KTLS_WRITING = 2 } ktls_step;

/* No descriptor, by design. NULL on failure. */
ktls_exchange *ktls_exchange_open(ktls_keys *keys, ktls_role role);
void ktls_exchange_free(ktls_exchange *x);

/* Hand over bytes that arrived from the peer. 0, or -1 on failure. */
int ktls_exchange_feed(ktls_exchange *x, const void *bytes, size_t len);

/* Copy out bytes that must reach the peer, and return how many. 0
 * means nothing is owed. */
size_t ktls_exchange_take(ktls_exchange *x, void *out, size_t cap);

/* Advance. 0 with *step == KTLS_DONE when the keys are agreed; 0 with
 * KTLS_READING or KTLS_WRITING to be called again once that has
 * happened; -1 on a real failure. Always drain ktls_exchange_take
 * afterwards: a step that answers KTLS_READING may still owe bytes. */
int ktls_exchange_step(ktls_exchange *x, ktls_step *step);

/* The protocol ALPN settled on, or NULL if the peer named none. Valid
 * until ktls_exchange_free. */
const char *ktls_exchange_alpn(const ktls_exchange *x, size_t *len);

/* RFC 8446 4.6.1: a peer may put application data in the same flight
 * as its Finished, so plaintext can already be waiting when the
 * exchange finishes. The kernel's stream starts at sequence zero and
 * cannot be handed a backlog, so this must be drained after KTLS_DONE
 * and processed before anything the socket delivers afterwards.
 *
 * Call it on BOTH sides even when no application data is expected: it
 * is also what consumes post-handshake records, and a NewSessionTicket
 * a peer has not consumed leaves the two sides disagreeing about where
 * the record sequence stands. A zero return does not mean nothing
 * happened. */
size_t ktls_exchange_backlog(ktls_exchange *x, void *out, size_t cap);

/* ---- the handover ------------------------------------------------ */

typedef enum { KTLS_TX = 0, KTLS_RX = 1 } ktls_direction;

/* The bytes for setsockopt(SOL_TLS, TLS_TX | TLS_RX). Take these LAST:
 * a TLS 1.3 key change resets the record sequence, and the kernel has
 * to continue from where the application keys already stood - after
 * the NewSessionTickets a server writes and after any backlog. So
 * this fails while ktls_exchange_take still owes bytes, and it must
 * be called after ktls_exchange_backlog has been drained. The
 * socket option level and name are ktls_sol_tls() and ktls_optname(),
 * so a reactor can submit the setsockopt however it likes - over
 * io_uring against a direct descriptor, for instance. */
const void *ktls_crypto_info(const ktls_exchange *x, ktls_direction dir, size_t *len);
int ktls_sol_tls(void);
int ktls_optname(ktls_direction dir);

/* How many application records this direction has already spent - what
 * the kernel is told to continue from. */
uint64_t ktls_record_sequence(const ktls_exchange *x, ktls_direction dir);

/* The suite that was negotiated, by its IANA name. */
const char *ktls_exchange_cipher(const ktls_exchange *x);

/* Give up the SSL and its buffers - the largest thing an exchange
 * holds - while keeping what a live connection still needs: the
 * traffic secrets, so a KeyUpdate can be answered, and the negotiated
 * cipher and ALPN, which are written down at KTLS_DONE for this.
 *
 * After it, feed, take, step and backlog all fail by name; crypto_info,
 * record_sequence, record_limit, alpn, cipher and next_key go on
 * answering. Call it once the handover is submitted and keep the
 * exchange for as long as the connection lives. ktls_exchange_free is
 * still what ends it.
 *
 * A caller that will never rekey may simply free instead. */
void ktls_exchange_release(ktls_exchange *x);

/* What a record on an offloaded socket turned out to be. A plain recv
 * answers EIO for anything but DATA and says no more than that. */
typedef enum {
  KTLS_RECORD_DATA = 0,      /* application data: the stream itself */
  KTLS_RECORD_ALERT = 1,     /* RFC 8446 6, close_notify among them */
  KTLS_RECORD_HANDSHAKE = 2, /* post-handshake: a KeyUpdate, a ticket */
  KTLS_RECORD_UNKNOWN = 3
} ktls_record;

/* The cmsg_type that carries it, and how to read it out of the control
 * message's payload. Two calls rather than a constant because the two
 * platforms disagree on both: Linux sends TLS_GET_RECORD_TYPE with one
 * byte, FreeBSD sends TLS_GET_RECORD with a struct. A caller that uses
 * these needs no <linux/tls.h> and no #ifdef.
 *
 * ktls_record_type answers KTLS_RECORD_UNKNOWN for a payload it cannot
 * read, which is also the answer for a control message that was never
 * there. */
int ktls_record_type_cmsg(void);
ktls_record ktls_record_type(const void *cmsg_data, size_t len);

/* And the same in the other direction, for the one record this side
 * spells deliberately: RFC 8446 6.1's close_notify, which a peer needs
 * in order to tell a finished stream from a truncated one. The kernel
 * encrypts whatever type it is told, so this needs no library beyond
 * the two names - the cmsg_type to set, and the payload for a kind.
 *
 * ktls_record_type_encode writes that payload and returns its length,
 * or 0 for a kind this platform will not let a caller send. */
int ktls_record_type_set_cmsg(void);
size_t ktls_record_type_encode(ktls_record kind, void *out, size_t cap);

/* RFC 8446 4.6.3: a peer may send a KeyUpdate at any time, and a
 * kernel-owned socket surfaces it as KTLS_RECORD_HANDSHAKE - which is
 * why the receive side has to be read with recvmsg and the control
 * message above, never a plain recv. Turning the secret one notch and
 * re-installing the crypto_info for that direction is the whole
 * answer; the sequence restarts at zero. */
int ktls_next_key(ktls_exchange *x, ktls_direction dir);

/* How many records this cipher may encrypt under one key before that
 * has to happen. 0 means no limit worth counting - ChaCha's answer.
 * AES-GCM answers half of RFC 8446 5.5's 2^24.5, so there is room to
 * act. After the handover the kernel writes the records, so the
 * caller bounds them: every sendmsg is at least one record and at
 * most ceil(len / 16384). */
uint64_t ktls_record_limit(const ktls_exchange *x);

/* setsockopt(TCP_ULP, "tls") on fd. Must come before either
 * crypto_info is installed. 0, or -1 with errno set. */
int ktls_attach_ulp(int fd);

/* ULP plus BOTH directions, on a descriptor this process holds. Both
 * or neither: a socket the kernel only half owns puts the record
 * layer back in this process for everything coming in, which is the
 * arrangement this library exists to avoid. 0, or -1. After it the
 * exchange may be freed and the socket speaks TLS by itself. */
int ktls_offload(const ktls_exchange *x, int fd);

#ifdef __cplusplus
}
#endif

#endif /* KTLS_H */
