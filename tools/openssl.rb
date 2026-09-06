# Which OpenSSL this gem builds against, and the refusal when there is
# none.
#
# The answer is NOT "whatever pkg-config says for libssl". openSUSE lets
# LibreSSL own /usr/lib64/pkgconfig/libssl.pc, so a machine whose
# `openssl version` says 3.5.3 hands a build LibreSSL 4.3.2 headers -
# which have neither EVP_KDF TLS13-KDF nor kTLS. src/ktls.c refuses to
# compile against those, and a refusal at the first #error is a wall of
# preprocessor text. This says it earlier, by name.
#
# So a candidate is taken only when its OWN header agrees:
#
#   - openssl/opensslv.h has no LIBRESSL_VERSION_TEXT,
#   - OPENSSL_VERSION_MAJOR is 3 or more,
#   - a compile against its headers does not see OPENSSL_NO_KTLS.
#
# The last one is a COMPILE and not a grep, because the macro reaches
# the source through whichever configuration header ssl.h pulls in, and
# which file that is differs by distribution. bio.h asks the same
# question the same way: `#ifndef OPENSSL_NO_KTLS` decides whether
# BIO_get_ktls_send is BIO_ctrl or the constant 0. Reading the name out
# of a header of our choosing would answer for the wrong file.
#
# OPENSSL_PKG_CONFIG names one module and skips the search.
# PKG_CONFIG_PATH works as it always does, which is how an operator
# points at a build under a prefix of their own.
module KtlsOpenSSL
  CANDIDATES = %w[libssl openssl openssl3 libopenssl libopenssl-3].freeze

  module_function

  # {cflags:, libs:, version:, module:} or nil.
  def find
    names = ENV['OPENSSL_PKG_CONFIG'] ? [ENV['OPENSSL_PKG_CONFIG']] : CANDIDATES
    names.each do |name|
      next unless pkg_config?(name)
      inc = `pkg-config --variable=includedir #{name} 2>/dev/null`.strip
      inc = '/usr/include' if inc.empty?
      cflags = `pkg-config --cflags #{name} 2>/dev/null`.strip
      next if refuse(inc, cflags)

      return {
        module: name,
        version: `pkg-config --modversion #{name} 2>/dev/null`.strip,
        cflags: cflags,
        libs: `pkg-config --libs #{name} 2>/dev/null`.strip
      }
    end
    nil
  end

  # Why this include directory cannot serve, or nil when it can.
  def refuse(inc, cflags = '')
    v = "#{inc}/openssl/opensslv.h"
    return "no openssl/opensslv.h under #{inc}" unless File.file?(v)

    text = File.read(v)
    return "LibreSSL, which has no TLS13-KDF and no kTLS" if text.include?('LIBRESSL_VERSION_TEXT')

    major = text[/define\s+OPENSSL_VERSION_MAJOR\s+(\d+)/, 1].to_i
    return "OpenSSL #{major}.x; TLS13-KDF arrived in 3.0" if major < 3

    ktls?(cflags) ? nil : 'an OpenSSL without the kTLS entry points'
  end

  # Does a compile against THESE headers have kTLS? SSL_OP_ENABLE_KTLS
  # must exist, and OPENSSL_NO_KTLS must not - the same condition bio.h
  # itself uses.
  def ktls?(cflags)
    require 'tempfile'
    src = Tempfile.new(['ktls-probe', '.c'])
    src.write(<<~PROBE)
      #include <openssl/ssl.h>
      #include <openssl/bio.h>
      #ifdef OPENSSL_NO_KTLS
      #error "built without kTLS"
      #endif
      static unsigned long probe(void) { return (unsigned long)SSL_OP_ENABLE_KTLS; }
    PROBE
    src.close
    cc = ENV['CC'] || 'cc'
    system(*[cc, *cflags.split, '-fsyntax-only', src.path],
           out: File::NULL, err: File::NULL)
  ensure
    src&.unlink
  end

  def pkg_config?(name)
    system('pkg-config', '--exists', name, out: File::NULL, err: File::NULL)
  end

  # What a machine without one has to do, per distribution. Named
  # packages, because "install OpenSSL" is not an instruction.
  def refusal_message
    <<~MSG
      [mruby-ktls] no OpenSSL >= 3.0 with kTLS was found.

      This gem hands the record layer to the kernel, so it needs OpenSSL's
      key schedule (EVP_KDF TLS13-KDF, OpenSSL 3.0) and its kTLS entry
      points. LibreSSL has neither.

      What was asked: pkg-config for #{CANDIDATES.join(', ')}.
      Name one yourself with OPENSSL_PKG_CONFIG=, or point
      PKG_CONFIG_PATH at a prefix of your own.

      openSUSE   zypper install libopenssl-3-devel
                 LibreSSL owns /usr/lib64/pkgconfig/libssl.pc there, so a
                 machine with libressl-devel hands every build LibreSSL
                 headers while `openssl version` says OpenSSL. The two
                 -devel packages cannot both be installed; the other
                 -devel packages take libopenssl-3-devel just as happily.
      Fedora     dnf install openssl-devel
      Arch       pacman -S openssl
      Debian     apt install libssl-dev
      Ubuntu     apt install libssl-dev
                 24.04's OpenSSL 3.0.13 carries no kTLS entry points. A
                 build of your own is the way out:
                   ./Configure --prefix=$HOME/.local/openssl shared enable-ktls
                   make -j$(nproc) && make install_sw
                   export PKG_CONFIG_PATH=$HOME/.local/openssl/lib64/pkgconfig:$PKG_CONFIG_PATH
    MSG
  end
end
