MRuby::Gem::Specification.new('mruby-ktls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'kTLS for mruby: an s2n-tls handshake that hands the wire to the kernel'

  # The Amazon stack, built to the MINIMUM that carries kTLS: AWS-LC's
  # libcrypto (its libssl is never built - s2n is the TLS layer) and
  # s2n-tls, both static, both pinned as submodules. cmake runs once
  # per build dir; a warm rebuild costs a stat.
  if ENV['OS'] != 'Windows_NT'
    awslc = "#{dir}/deps/aws-lc"
    s2n   = "#{dir}/deps/s2n-tls"
    bdir  = "#{build_dir}/deps"
    libcrypto = "#{bdir}/aws-lc/crypto/libcrypto.a"
    libs2n    = "#{bdir}/s2n/lib/libs2n.a"
    prefix    = "#{bdir}/prefix"

    unless File.file?(libcrypto)
      sh %(cmake -S "#{awslc}" -B "#{bdir}/aws-lc" -DCMAKE_BUILD_TYPE=Release ) +
         %(-DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DDISABLE_GO=ON ) +
         %(-DDISABLE_PERL=ON -DBUILD_TOOL=OFF >/dev/null)
      sh %(cmake --build "#{bdir}/aws-lc" --target crypto -j#{`nproc`.strip} >/dev/null)
    end
    unless File.file?(libs2n)
      # s2n finds libcrypto through a prefix; stage the crypto-only
      # slice of AWS-LC as one (headers straight from the source tree,
      # which ships them pregenerated).
      FileUtils.mkdir_p ["#{prefix}/lib", "#{prefix}/include"]
      FileUtils.cp libcrypto, "#{prefix}/lib/"
      FileUtils.cp_r "#{awslc}/include/openssl", "#{prefix}/include/", remove_destination: true
      sh %(cmake -S "#{s2n}" -B "#{bdir}/s2n" -DCMAKE_BUILD_TYPE=Release ) +
         %(-DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF ) +
         %(-DCMAKE_PREFIX_PATH="#{prefix}" >/dev/null)
      sh %(cmake --build "#{bdir}/s2n" -j#{`nproc`.strip} >/dev/null)
    end

    spec.cc.include_paths << "#{s2n}/api"
    # Order matters: s2n resolves into crypto.
    spec.linker.flags_after_libraries += [libs2n, libcrypto]
  end

  spec.add_test_dependency 'mruby-io'
  spec.add_test_dependency 'mruby-socket'
  spec.add_test_dependency 'mruby-errno'
  spec.add_test_dependency 'mruby-string-ext'
end
