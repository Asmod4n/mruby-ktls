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
    # EVERY time, not only when the tree is empty. `update = none` in
    # .gitmodules means a plain `git submodule update` never moves this
    # one, so a pin that moved would leave an old OpenSSL on disk and
    # nothing would say so. At the pinned commit the call does nothing.
    fetch_source(src)
    unless File.file?("#{src}/Configure")
      raise "[mruby-ktls] #{src} has no OpenSSL - run: " \
            "git submodule update --init --depth 1 --checkout deps/openssl"
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

  # The OpenSSL source, taken by name. .gitmodules marks it `update =
  # none` so that a recursive clone does not drag in the eleven
  # repositories OpenSSL lists as ITS submodules - test material for
  # other projects, 581 MB of it. --checkout overrides that mark for
  # this one, --depth 1 keeps the history off, and `git submodule
  # update` does not recurse unless it is told to.
  #
  # Silent when it cannot run: a source tree that was unpacked from a
  # tarball has no .git, and the raise above says what to do.
  def fetch_source(src)
    root = File.expand_path('..', File.dirname(src))
    return unless File.exist?("#{root}/.git")

    Dir.chdir(root) do
      system('git', 'submodule', 'update', '--init', '--depth', '1', '--checkout',
             src.sub("#{root}/", ''), out: File::NULL)
    end
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
