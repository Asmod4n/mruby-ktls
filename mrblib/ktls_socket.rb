# The socket API, subclassed: users keep TCPSocket's surface and only
# the methods that must stay under s2n's eyes are replaced. #write
# routes through s2n_send - which, after the kTLS handover, submits
# through the OFFLOADED socket (kernel crypto) while s2n keeps the
# record accounting and emits KeyUpdates when due. #recv routes
# through s2n_recv, which processes an incoming KeyUpdate instead of
# surfacing EIO. Everything inherited (fileno, addresses, options,
# select-ability) is untouched - IO.select works because the fd is
# real. The three "unsafe" caveats dissolve here by construction; the
# raw-fd escape stays available one level down (KTLS::Connection) for
# reactors that do their own accounting.

module KTLS
  class Socket < TCPSocket
    # Adopts a COPY of io's fd (dup): both objects own their
    # descriptor, either may close without killing the other.
    def self.attach(io, config, mode)
      sock = for_fd(KTLS.dup_fd(io.fileno))
      sock._ktls_init(config, mode)
      sock
    end

    def _ktls_init(config, mode)
      @ktls = Connection.new(config, self, mode)
      self
    end

    # One nonblocking handshake step: :done | :reading | :writing.
    # Reactors drive this; #handshake is the blocking convenience.
    def handshake_step
      @ktls.negotiate
    end

    def handshake
      loop do
        case handshake_step
        when :done then break
        when :writing then IO.select(nil, [self])
        else IO.select([self])
        end
      end
      try_enable if available?
      self
    end

    # The kTLS surface is THREE methods, whole:
    #   KTLS.enabled?  - is the tls subsystem initialized on this
    #                    host? Passive (/proc marker), loads nothing.
    #   #available?    - the same question, asked at the socket.
    #   #try_enable    - the handover; raises when it cannot.
    # No state mirror: s2n itself knows whether it is offloaded and
    # routes accordingly - the API above is identical either way.

    def available?
      KTLS.enabled?
    end

    # Hands the record layer to the kernel and RAISES when it cannot:
    # the "not initialized" refusal (load the tls module deliberately
    # - modprobe tls, or KTLS.probe) and s2n's own errors pass
    # through untouched. If it returns, the kernel owns the wire; a
    # caller who wants the shrug writes `try_enable if available?`.
    def try_enable
      @ktls.enable_ktls_send
      @ktls.enable_ktls_recv
      self
    end

    def version = @ktls.version
    def cipher = @ktls.cipher

    def write(str)
      str = str.to_s
      total = 0
      while total < str.bytesize
        n, status = @ktls.send(total == 0 ? str : str[total, str.bytesize - total])
        total += n
        IO.select(nil, [self]) if status == :writing
      end
      total
    end

    def print(*args)
      args.each { |a| write(a) }
      nil
    end

    # One chunk, up to maxlen bytes; '' is end of stream (the peer's
    # close_notify or close), matching TCPSocket#recv.
    def recv(maxlen, _flags = 0)
      loop do
        chunk, status = @ktls.recv(maxlen)
        return chunk unless chunk.empty?
        return '' if status == :done
        IO.select([self])
      end
    end

    def readpartial(maxlen)
      chunk = recv(maxlen)
      raise EOFError, 'end of stream' if chunk.empty?
      chunk
    end

    def read(length = nil)
      return recv(65536) if length.nil?
      out = ''
      while out.bytesize < length
        chunk = recv(length - out.bytesize)
        break if chunk.empty?
        out << chunk
      end
      out
    end

    def close
      # Best-effort close_notify (RFC 8446 6.1): one shutdown step; a
      # gone peer must not make closing raise.
      begin
        @ktls.shutdown
      rescue RuntimeError
        nil
      end
      super
    end
  end
end
