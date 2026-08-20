# The surface that exists today, proven by doing.

assert('KTLS.supported? answers a boolean by probing, not guessing') do
  v = KTLS.supported?
  assert_true v == true || v == false
end

assert('KTLS.ulp refuses a socket that is not ESTABLISHED, with errno') do
  skip 'kTLS not available on this host' unless KTLS.supported?
  # TCP_ULP demands an established TCP socket; a fresh unconnected one
  # is refused by the kernel (ENOTCONN), and the refusal must arrive
  # as SystemCallError, not as silence.
  sock = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM)
  begin
    assert_raise(SystemCallError) { KTLS.ulp(sock) }
  ensure
    sock.close
  end
end

assert('KTLS.ulp attaches to an established loopback pair') do
  skip 'kTLS not available on this host' unless KTLS.supported?
  server = TCPServer.new('127.0.0.1', 0)
  port = server.local_address.ip_port
  client = TCPSocket.new('127.0.0.1', port)
  peer = server.accept
  begin
    assert_equal client, KTLS.ulp(client)
  ensure
    client.close
    peer.close
    server.close
  end
end
