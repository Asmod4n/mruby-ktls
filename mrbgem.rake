require 'fileutils'

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
    unless File.file?("#{ossl_src}/Configure")
      raise "[mruby-ktls] deps/openssl is empty - run: git submodule update --init --depth 1"
    end

    ossl = "#{build_dir}/openssl"
    libssl = "#{ossl}/libssl.so"

    # Out of tree, so the submodule stays pristine and a second build
    # config does not fight this one over generated headers.
    #
    # The no- list is what "only the part we need" means for OpenSSL:
    # the knobs are the supported granularity, a source-level slice is
    # not. TLS 1.3 is the only protocol this tree speaks.
    unless File.file?(libssl)
      FileUtils.mkdir_p(ossl)
      Dir.chdir(ossl) do
        sh "perl #{ossl_src}/Configure shared enable-ktls " \
           "no-tests no-docs no-dtls no-ssl3 no-tls1 no-tls1_1 " \
           "no-comp no-engine no-dso no-legacy no-deprecated no-quic " \
           "no-ssl-trace no-uplink > configure.log 2>&1"
        sh "make -j#{`nproc`.strip} build_libs >> configure.log 2>&1"
      end
    end

    spec.cc.include_paths  << "#{ossl}/include" << "#{ossl_src}/include"
    spec.cxx.include_paths << "#{ossl}/include" << "#{ossl_src}/include"
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
