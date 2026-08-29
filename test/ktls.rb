# The Ruby surface, proven the way the C one is: a whole TLS 1.3
# exchange between two KTLS::Exchange objects in one process, with no
# socket anywhere. The strongest check available without a tls ULP is
# that the server's SEND blob and the client's RECEIVE blob are the
# same bytes - a wrong direction or a miscounted record sequence
# breaks exactly there. The cert is a 100-year self-signed P-256 for
# localhost, generated once for this test and worth nothing.

TEST_CERT = "-----BEGIN CERTIFICATE-----\n" \
  "MIIBgDCCASWgAwIBAgIUNNKnAr1se/+WxaBe3ALOeOjWB3swCgYIKoZIzj0EAwIw\n" \
  "FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDgyMDEwMzUzMVoYDzIxMjYwNzI3\n" \
  "MTAzNTMxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\n" \
  "PQMBBwNCAAQcvU5lmq705wsQT6YX2xDLO/VY1e72efz3WSg779yfYlrzls9aKHin\n" \
  "va0Rk8na7yETBqzSRK/FOE+NVEZ8bD7eo1MwUTAdBgNVHQ4EFgQUwuwYX+KVWWJV\n" \
  "L6akXMZuH8LODncwHwYDVR0jBBgwFoAUwuwYX+KVWWJVL6akXMZuH8LODncwDwYD\n" \
  "VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA7PdtZjy1b4OXtZA27wsc\n" \
  "REWHd5WfH/xLeZKjvo6l+/4CIQDDVAS2p/+HzTRNfD7pkJBoztt7YnSXqLDtGpnF\n" \
  "xV6JZQ==\n" \
  "-----END CERTIFICATE-----\n"

TEST_KEY = "-----BEGIN PRIVATE KEY-----\n" \
  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQga5rJvcnKzH9eB65k\n" \
  "/fYatOwlgobgO1xuexSLYCuwM/2hRANCAAQcvU5lmq705wsQT6YX2xDLO/VY1e72\n" \
  "efz3WSg779yfYlrzls9aKHinva0Rk8na7yETBqzSRK/FOE+NVEZ8bD7e\n" \
  "-----END PRIVATE KEY-----\n"

def ktls_pair(suites = nil)
  sk = KTLS::Keys.server(TEST_CERT, TEST_KEY)
  ck = KTLS::Keys.client
  sk.alpn = ['h2', 'http/1.1']
  ck.alpn = ['h2', 'http/1.1']
  if suites
    sk.ciphers = suites
    ck.ciphers = suites
  end
  s = KTLS::Exchange.new(sk, :server)
  c = KTLS::Exchange.new(ck, :client)

  ss = cs = :reading
  64.times do
    break if ss == :done && cs == :done
    cs = c.step
    s.feed(c.take)
    ss = s.step
    c.feed(s.take)
  end
  # Post-handshake records - the two NewSessionTickets a server writes
  # under the application key - must be CONSUMED before the sequence is
  # read, on BOTH sides.
  s.backlog
  c.backlog
  [s, c, ss, cs, sk, ck]
end

assert('KTLS.initialized? answers passively - asking loads nothing') do
  v = KTLS.initialized?
  assert_true v == true || v == false
  assert_equal v, KTLS.initialized?
end

assert('KTLS.available? can never be outrun by initialized?') do
  assert_true KTLS.available? || !KTLS.initialized?
end

assert('a whole exchange runs with no descriptor named anywhere') do
  s, c, ss, cs, = ktls_pair
  assert_equal :done, ss
  assert_equal :done, cs
  assert_equal 'h2', s.alpn
  assert_equal s.cipher, c.cipher
end

assert('the server SENDS with what the client RECEIVES with') do
  s, c, = ktls_pair
  assert_equal s.crypto_info(:tx), c.crypto_info(:rx)
  assert_equal c.crypto_info(:tx), s.crypto_info(:rx)
  assert_true s.crypto_info(:tx) != s.crypto_info(:rx)
end

assert('the session tickets moved the record sequence - zero would be nonce reuse') do
  s, c, = ktls_pair
  assert_true s.record_sequence(:tx) > 0
  assert_equal s.record_sequence(:tx), c.record_sequence(:rx)
  # The client sent no application record, so the server read none.
  assert_equal 0, s.record_sequence(:rx)
end

assert('the blob is the size the negotiated cipher\'s struct has') do
  s, = ktls_pair('TLS_AES_128_GCM_SHA256')
  assert_equal 'TLS_AES_128_GCM_SHA256', s.cipher
  assert_equal 40, s.crypto_info(:tx).bytesize   # info 4 + iv 8 + key 16 + salt 4 + seq 8
  assert_true s.record_limit > 0                 # AES-GCM has one worth counting

  s2, = ktls_pair('TLS_CHACHA20_POLY1305_SHA256')
  assert_equal 'TLS_CHACHA20_POLY1305_SHA256', s2.cipher
  assert_equal 56, s2.crypto_info(:tx).bytesize  # info 4 + iv 12 + key 32 + salt 0 + seq 8
  assert_equal 0, s2.record_limit                # ChaCha has none anyone reaches
end

assert('a KeyUpdate leaves the two sides still agreeing') do
  s, c, = ktls_pair
  before = s.crypto_info(:tx)
  s.next_key(:tx)
  c.next_key(:rx)
  assert_true s.crypto_info(:tx) != before
  assert_equal s.crypto_info(:tx), c.crypto_info(:rx)
  # A key change restarts the sequence.
  assert_equal 0, s.record_sequence(:tx)
end

assert('the handover refuses by name where the tls module is not loaded') do
  skip 'this kernel has kTLS' if KTLS.initialized?
  s, = ktls_pair
  assert_raise(KTLS::Error) { s.offload(0) }
end
