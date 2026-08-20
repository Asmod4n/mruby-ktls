MRuby::Gem::Specification.new('mruby-ktls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Kernel TLS (TLS_TX/TLS_RX) for mruby sockets'

  # Linux-only by nature: kTLS is a Linux socket ULP. On anything else
  # the gem compiles to a module whose supported? answers false and
  # whose operations raise NotImplementedError - see src/mrb_ktls.c.

  spec.add_test_dependency 'mruby-io'
  spec.add_test_dependency 'mruby-socket'
  spec.add_test_dependency 'mruby-errno'
end
