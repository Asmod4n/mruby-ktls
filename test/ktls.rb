# The surface, proven by doing: a real handshake on a loopback pair,
# single-threaded - both ends step their nonblocking negotiate until
# each answers :done, exactly the shape a one-thread reactor drives.
# The kTLS handover itself is proven where CONFIG_TLS exists and skips
# by name where it does not. The cert is a 100-year self-signed P-256
# for localhost, generated once for this test and worth nothing.

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

assert('KTLS.supported? answers a boolean by probing, not guessing') do
  v = KTLS.supported?
  assert_true v == true || v == false
end

assert('KTLS.ulp refuses a socket that is not ESTABLISHED, with errno') do
  skip 'kTLS not available on this host' unless KTLS.supported?
  sock = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM)
  begin
    assert_raise(SystemCallError) { KTLS.ulp(sock) }
  ensure
    sock.close
  end
end

def ktls_loopback_pair
  server = TCPServer.new('127.0.0.1', 0)
  client = TCPSocket.new('127.0.0.1', server.local_address.ip_port)
  peer = server.accept
  server.close
  [peer, client]
end

# Steps both nonblocking negotiations in one thread until done.
def ktls_handshake(sconn, cconn)
  s = c = :reading
  200.times do
    s = sconn.negotiate unless s == :done
    c = cconn.negotiate unless c == :done
    return true if s == :done && c == :done
  end
  false
end

assert('s2n: a loopback handshake completes, single-threaded, stepped') do
  scfg = KTLS::Config.server(TEST_CERT, TEST_KEY)
  ccfg = KTLS::Config.client
  speer, cpeer = ktls_loopback_pair
  begin
    sconn = KTLS::Connection.new(scfg, speer, :server)
    cconn = KTLS::Connection.new(ccfg, cpeer, :client)
    assert_true ktls_handshake(sconn, cconn), 'handshake never completed'
    # TLS 1.3 is mandatory: the default policy's minimum enforces it.
    assert_equal :tls13, sconn.version
    assert_equal :tls13, cconn.version
    # Application data through s2n, pre-handover.
    n, = cconn.send('hello over tls')
    assert_equal 14, n
    got = ''
    20.times do
      chunk, = sconn.recv(64)
      got << chunk
      break if got.bytesize == 14
    end
    assert_equal 'hello over tls', got
  ensure
    speer.close
    cpeer.close
  end
end

assert('kTLS handover: after enable, plain socket I/O IS the TLS channel') do
  skip 'kTLS not available on this host' unless KTLS.supported?
  scfg = KTLS::Config.server(TEST_CERT, TEST_KEY)
  ccfg = KTLS::Config.client
  speer, cpeer = ktls_loopback_pair
  begin
    sconn = KTLS::Connection.new(scfg, speer, :server)
    cconn = KTLS::Connection.new(ccfg, cpeer, :client)
    assert_true ktls_handshake(sconn, cconn)
    sconn.ktls_send!  # the server's send path belongs to the kernel now
    # A plain write on the server fd arrives decrypted through s2n on
    # the client: the kernel wrote the TLS record.
    speer.write('kernel wrote this')
    got = ''
    20.times do
      chunk, = cconn.recv(64)
      got << chunk
      break if got.bytesize == 17
    end
    assert_equal 'kernel wrote this', got
  ensure
    speer.close
    cpeer.close
  end
end
