require_relative 'tools/openssl'

MRuby::Gem::Specification.new('mruby-ktls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'kTLS for mruby: agree keys, hand them to the kernel, get out of the way'

  # include/ktls.h and include/ktls.hpp are the whole surface. mruby
  # puts a gem's include/ on every dependent's compiler path, so a C or
  # C++ gem that depends on this one has them without saying so;
  # export_include_paths carries them to mruby-config users too.
  spec.export_include_paths << "#{spec.dir}/include"

  # OpenSSL >= 3.0 with kTLS, from the machine. This gem hands the
  # record layer to the kernel, so it needs OpenSSL's key schedule
  # (EVP_KDF TLS13-KDF) and its kTLS entry points.
  #
  # NOT a bare `pkg-config libssl`: openSUSE lets LibreSSL own that
  # name, so a machine whose `openssl version` says OpenSSL 3.5.3 hands
  # a build LibreSSL headers. tools/openssl.rb asks several names, reads
  # the header behind each answer, and takes the first that is OpenSSL
  # 3.0 or later with kTLS. OPENSSL_PKG_CONFIG= names one; PKG_CONFIG_PATH
  # points at a prefix of your own.
  if RUBY_PLATFORM !~ /mswin|mingw|windows/
    ossl = KtlsOpenSSL.find or abort(KtlsOpenSSL.refusal_message)

    flags = ossl[:cflags].split
    spec.cc.flags  += flags
    spec.cxx.flags += flags
    # A gem that depends on this one compiles against the same headers -
    # two libcryptos in one address space is a bug waiting for a link
    # order.
    spec.export_include_paths += flags.grep(/\A-I/).map { |f| f[2..] }
    spec.linker.flags_after_libraries += ossl[:libs].split + ['-lcrypto']
  end

  spec.add_dependency 'mruby-io',    core: 'mruby-io'
  spec.add_dependency 'mruby-error', core: 'mruby-error'
  spec.add_test_dependency 'mruby-socket', core: 'mruby-socket'
  spec.add_test_dependency 'mruby-string-ext', core: 'mruby-string-ext'
end
