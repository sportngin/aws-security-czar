# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ec2-security-czar/version'

Gem::Specification.new do |spec|
  spec.name          = "ec2-security-czar"
  spec.version       = Ec2SecurityCzar::VERSION
  spec.authors       = ["Ian Ehlert"]
  spec.email         = ["ehlertij@gmail.com"]
  spec.summary       = %q{Rule manager for EC2 Security Groups.}
  spec.description   = %q{Manages your EC2 security groups using YAML config files.}
  spec.homepage      = "https://github.com/sportngin/ec2-security-czar"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "aws-sdk", "~> 1.38"

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec", "3.0.0.beta2"
  spec.add_development_dependency "guard"
  spec.add_development_dependency "guard-rspec"
  spec.add_development_dependency "terminal-notifier-guard"
  spec.add_development_dependency "simplecov"
end
