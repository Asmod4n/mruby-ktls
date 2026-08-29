/*
 * ktls.hpp - the same API, with the frees written down once.
 *
 * A thin layer over ktls.h: move-only handles, no exceptions, no
 * allocation of its own. Every method is one call deep, so what a C
 * caller reads in ktls.h is what happens here.
 */
#ifndef KTLS_HPP
#define KTLS_HPP

#include "ktls.h"

#include <cstddef>
#include <utility>

namespace ktls {

inline const char* last_error() { return ktls_last_error(); }
inline bool initialized() { return ktls_initialized(); }
inline bool available() { return ktls_available(); }
inline bool aes_is_fast() { return ktls_aes_is_fast(); }
inline int load_module() { return ktls_load_module(); }
inline int attach_ulp(int fd) { return ktls_attach_ulp(fd); }
inline int sol_tls() { return ktls_sol_tls(); }
inline int optname(ktls_direction dir) { return ktls_optname(dir); }

// The cert chain and private key one listener answers with. Must
// outlive every Exchange opened from it.
class Keys {
 public:
  Keys() = default;
  static Keys server(const char* cert_pem, size_t cert_len, const char* key_pem, size_t key_len) {
    return Keys(ktls_keys_server(cert_pem, cert_len, key_pem, key_len));
  }
  static Keys client() { return Keys(ktls_keys_client()); }

  Keys(Keys&& o) noexcept : k_(o.k_) { o.k_ = nullptr; }
  Keys& operator=(Keys&& o) noexcept {
    if (this != &o) { ktls_keys_free(k_); k_ = o.k_; o.k_ = nullptr; }
    return *this;
  }
  Keys(const Keys&) = delete;
  Keys& operator=(const Keys&) = delete;
  ~Keys() { ktls_keys_free(k_); }

  explicit operator bool() const { return k_ != nullptr; }
  ktls_keys* get() const { return k_; }

  int set_alpn(const char* const* protocols, size_t count) {
    return ktls_keys_set_alpn(k_, protocols, count);
  }
  int set_ciphers(const char* suites) { return ktls_keys_set_ciphers(k_, suites); }

 private:
  explicit Keys(ktls_keys* k) : k_(k) {}
  ktls_keys* k_ = nullptr;
};

// One key exchange. Names no descriptor: bytes cross through feed and
// take, so the socket stays whoever's it was.
class Exchange {
 public:
  Exchange() = default;
  static Exchange open(const Keys& keys, ktls_role role) {
    return Exchange(ktls_exchange_open(keys.get(), role));
  }

  Exchange(Exchange&& o) noexcept : x_(o.x_) { o.x_ = nullptr; }
  Exchange& operator=(Exchange&& o) noexcept {
    if (this != &o) { ktls_exchange_free(x_); x_ = o.x_; o.x_ = nullptr; }
    return *this;
  }
  Exchange(const Exchange&) = delete;
  Exchange& operator=(const Exchange&) = delete;
  ~Exchange() { ktls_exchange_free(x_); }

  explicit operator bool() const { return x_ != nullptr; }

  int feed(const void* bytes, size_t len) { return ktls_exchange_feed(x_, bytes, len); }
  size_t take(void* out, size_t cap) { return ktls_exchange_take(x_, out, cap); }
  int step(ktls_step* s) { return ktls_exchange_step(x_, s); }
  size_t backlog(void* out, size_t cap) { return ktls_exchange_backlog(x_, out, cap); }

  const char* alpn(size_t* len) const { return ktls_exchange_alpn(x_, len); }
  const char* cipher() const { return ktls_exchange_cipher(x_); }

  // Read LAST: the sequence is only settled once nothing is owed and
  // the backlog is drained.
  const void* crypto_info(ktls_direction dir, size_t* len) const {
    return ktls_crypto_info(x_, dir, len);
  }
  uint64_t record_sequence(ktls_direction dir) const { return ktls_record_sequence(x_, dir); }
  uint64_t record_limit() const { return ktls_record_limit(x_); }
  int next_key(ktls_direction dir) { return ktls_next_key(x_, dir); }
  int offload(int fd) const { return ktls_offload(x_, fd); }

 private:
  explicit Exchange(ktls_exchange* x) : x_(x) {}
  ktls_exchange* x_ = nullptr;
};

}  // namespace ktls

#endif  // KTLS_HPP
