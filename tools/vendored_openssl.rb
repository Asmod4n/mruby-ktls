require 'fileutils'

# The vendored OpenSSL build, in ONE place: mrbgem.rake builds it into
# the mruby build tree, the Rakefile builds it for the standalone
# examples, and neither spells the Configure line itself.
#
# The no- list is what "only the part we need" means here. OpenSSL's
# knobs are the supported granularity; a source-level slice is not.
# TLS 1.3 is the only protocol this library speaks.
#
# no-apps is NOT among them on purpose: it breaks the out-of-tree
# Configure, which then writes apps/include/configuration.h.in.new into
# a source directory it was just told not to have. build_libs does not
# build the apps anyway.
module VendoredOpenSSL
  OPTIONS = %w[
    shared enable-ktls
    no-tests no-docs no-dtls no-ssl3 no-tls1 no-tls1_1
    no-comp no-engine no-dso no-legacy no-deprecated no-quic
    no-ssl-trace no-uplink
  ].freeze

  module_function

  # Returns the build directory, which holds libssl.so, libcrypto.so and
  # the generated include/openssl. Builds it if it is not there yet.
  def build(src, dest)
    unless File.file?("#{src}/Configure")
      raise "[mruby-ktls] #{src} is empty - run: git submodule update --init --depth 1"
    end
    return dest if File.file?("#{dest}/libssl.so")

    FileUtils.mkdir_p(dest)
    log = "#{dest}/build.log"
    Dir.chdir(dest) do
      sh_quiet("perl #{src}/Configure #{OPTIONS.join(' ')}", log)
      sh_quiet("make -j#{jobs} build_libs", log)
    end
    dest
  end

  # The two -I paths a caller needs: generated headers first, then the
  # ones that ship with the source.
  def include_paths(src, dest)
    ["#{dest}/include", "#{src}/include"]
  end

  def jobs
    `nproc 2>/dev/null`.strip.to_i.nonzero? || 4
  end

  def sh_quiet(cmd, log)
    ok = system("#{cmd} >> #{log} 2>&1")
    raise "[mruby-ktls] failed: #{cmd}\n  see #{log}" unless ok
  end
end
