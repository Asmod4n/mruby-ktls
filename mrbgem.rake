require_relative 'tools/vendored_openssl'

MRuby::Gem::Specification.new('mruby-ktls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'kTLS for mruby: agree keys, hand them to the kernel, get out of the way'

  # include/ktls.h and include/ktls.hpp are the whole surface. mruby
  # puts a gem's include/ on every dependent's compiler path, so a C or
  # C++ gem that depends on this one has them without saying so;
  # export_include_paths carries them to mruby-config users too.
  spec.export_include_paths << "#{spec.dir}/include"

  # OpenSSL >= 3.0, vendored and built here, because the answer to
  # "which crypto library is on this machine" is not one a server may
  # depend on: openSUSE ships LibreSSL, which has neither EVP_KDF
  # TLS13-KDF nor kTLS, and Ubuntu's OpenSSL 3.0.13 is built without
  # kTLS at all (its libssl.so.3 exports no ktls symbol). src/ktls.c
  # refuses to compile against either, by #error and by name.
  #
  # SHARED on purpose: the process that speaks TLS is not the process
  # that serves HTTP (see README, "Four processes"), and a shared
  # object is what lets the two link different crypto without meeting.
  if RUBY_PLATFORM !~ /mswin|mingw|windows/
    ossl_src = "#{dir}/deps/openssl"
    ossl = VendoredOpenSSL.build(ossl_src, "#{build_dir}/openssl")

    inc = VendoredOpenSSL.include_paths(ossl_src, ossl)
    spec.cc.include_paths  += inc
    spec.cxx.include_paths += inc
    # RPATH so the binary finds the .so beside itself rather than the
    # distribution's - which is the whole point of vendoring it.
    spec.linker.flags_after_libraries += [
      "-L#{ossl}", '-lssl', '-lcrypto',
      "-Wl,-rpath,#{ossl}", "-Wl,-rpath,\\$ORIGIN/../lib"
    ]
  end

  spec.add_dependency 'mruby-io',    core: 'mruby-io'
  spec.add_dependency 'mruby-error', core: 'mruby-error'
  spec.add_test_dependency 'mruby-socket', core: 'mruby-socket'
  spec.add_test_dependency 'mruby-string-ext', core: 'mruby-string-ext'
end
