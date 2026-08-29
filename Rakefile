require 'rake'
require 'fileutils'

MRUBY_CONFIG_PATH = File.expand_path(ENV["MRUBY_CONFIG"] || "build_config.rb")

file :mruby do
  unless File.directory?('mruby')
    sh "git clone --depth=1 https://github.com/mruby/mruby.git"
  end
end

desc "compile binary"
task :compile => :mruby do
  Dir.chdir("mruby") do
    ENV["MRUBY_CONFIG"] = MRUBY_CONFIG_PATH
    sh "rake all"
  end
end

desc "test"
task :test => :mruby do
  Dir.chdir("mruby") do
    ENV["MRUBY_CONFIG"] = MRUBY_CONFIG_PATH
    sh "rake all test"
  end
end

desc "cleanup"
task :clean do
  Dir.chdir("mruby") do
    ENV["MRUBY_CONFIG"] = MRUBY_CONFIG_PATH
    sh "rake deep_clean"
  end
end

# --- the standalone programs -----------------------------------------
#
# They must NOT be built against the machine's TLS library. That is the
# whole point of vendoring one: openSUSE ships LibreSSL, which has
# neither EVP_KDF TLS13-KDF nor kTLS, and a distribution's OpenSSL may
# have kTLS compiled out. `pkg-config --libs openssl` finds exactly the
# wrong thing, and src/ktls.c says so by #error rather than building
# something that fails at runtime.

require_relative 'tools/vendored_openssl'

OSSL_SRC   = File.expand_path('deps/openssl', __dir__)
OSSL_BUILD = File.expand_path('build/openssl', __dir__)
EXAMPLES   = File.expand_path('build/examples', __dir__)

desc 'build the vendored OpenSSL (shared, with kTLS) - once, then cached'
task :openssl do
  VendoredOpenSSL.build(OSSL_SRC, OSSL_BUILD)
  puts "openssl: #{OSSL_BUILD}/libssl.so"
end

def compile_example(cc, src, out, std)
  inc = VendoredOpenSSL.include_paths(OSSL_SRC, OSSL_BUILD).map { |i| "-I#{i}" }.join(' ')
  FileUtils.mkdir_p(EXAMPLES)
  sh "#{cc} #{std} -D_GNU_SOURCE -O2 -Wall -Wextra -o #{EXAMPLES}/#{out} " \
     "#{src} src/ktls.c -Iinclude #{inc} " \
     "-L#{OSSL_BUILD} -lssl -lcrypto -Wl,-rpath,#{OSSL_BUILD} -lpthread -ldl"
end

desc 'build examples/ against the vendored OpenSSL'
task examples: :openssl do
  compile_example('cc',  'examples/ktls_c_api.c',     'ktls_c_api',     '-std=c11')
  compile_example('c++', 'examples/ktls_cpp_api.cpp', 'ktls_cpp_api',   '-std=c++20')
  compile_example('cc',  'examples/ktls_handover.c',  'ktls_handover',  '-std=c11')
  puts "built: #{EXAMPLES}"
end

desc 'the key exchange, proven from C and C++ - runs anywhere'
task exchange: :examples do
  sh "#{EXAMPLES}/ktls_c_api"
  sh "#{EXAMPLES}/ktls_c_api TLS_CHACHA20_POLY1305_SHA256"
  sh "#{EXAMPLES}/ktls_cpp_api"
end

desc 'the handover itself - needs a kernel with CONFIG_TLS'
task handover: :examples do
  ok = system("#{EXAMPLES}/ktls_handover")
  warn 'this kernel has no tls ULP - nothing was proven' if !ok && $?.exitstatus == 77
end

task :default => :test
