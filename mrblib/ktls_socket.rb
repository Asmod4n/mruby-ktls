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
      @offloaded = false
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
      offload
      self
    end

    # Hands the record layer to the kernel and RAISES when it cannot:
    # the "not initialized" refusal (load the tls module deliberately
    # - modprobe tls, or KTLS.probe) and s2n's own errors pass
    # through untouched. For callers whose deployment PROMISES kTLS
    # and who want the broken promise loud, not a false.
    def try_enable
      @ktls.enable_ktls_send
      @ktls.enable_ktls_recv
      @offloaded = true
      self
    end

    # The shrugging sibling: same handover, but a host that cannot
    # take it answers false and s2n keeps doing the crypto itself -
    # the API above stays identical either way (s2n routes sends
    # through the offloaded socket when it is offloaded). True = the
    # kernel owns the wire.
    def offload
      try_enable
      true
    rescue RuntimeError
      @offloaded = false
    end

    def offloaded?
      @offloaded
    end

    # The public question: can THIS host hand the record layer to the
    # kernel? PASSIVE (see KTLS.supported?): reads a /proc marker and
    # never loads the tls module. KTLS.probe is the deliberate loader.
    def ktls_available?
      KTLS.supported?
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
