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
# They build against the OpenSSL the machine offers, chosen by
# tools/openssl.rb rather than by a bare `pkg-config libssl`: openSUSE
# lets LibreSSL own that name, and LibreSSL has neither EVP_KDF
# TLS13-KDF nor kTLS. The probe reads the header behind every candidate
# and refuses by name, which is what src/ktls.c would otherwise say as
# a wall of #error text.

require_relative 'tools/openssl'

EXAMPLES = File.expand_path('build/examples', __dir__)

def openssl!
  @openssl ||= KtlsOpenSSL.find or abort(KtlsOpenSSL.refusal_message)
end

desc 'which OpenSSL this machine offers'
task :openssl do
  o = openssl!
  puts "openssl: #{o[:version]} through pkg-config #{o[:module]}"
  puts "  cflags: #{o[:cflags].empty? ? '(none)' : o[:cflags]}"
  puts "  libs:   #{o[:libs]}"
end

def compile_example(cc, src, out, std)
  o = openssl!
  FileUtils.mkdir_p(EXAMPLES)
  sh "#{cc} #{std} -D_GNU_SOURCE -O2 -Wall -Wextra -o #{EXAMPLES}/#{out} " \
     "#{src} src/ktls.c -Iinclude #{o[:cflags]} #{o[:libs]} -lcrypto -lpthread -ldl"
end

desc "build examples/ against the machine's OpenSSL"
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
