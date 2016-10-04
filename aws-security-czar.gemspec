# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'aws-security-czar/version'

Gem::Specification.new do |spec|
  spec.name          = "aws-security-czar"
  spec.version       = AwsSecurityCzar::VERSION
  spec.authors       = ["Ian Ehlert", "Matt Krieger"]
  spec.email         = ["platform-ops@sportsengine.com"]
  spec.summary       = %q{Rule manager for EC2 Security Groups.}
  spec.description   = %q{Manages your EC2 security groups using YAML config files.}
  spec.homepage      = "https://github.com/sportngin/ec2-security-czar"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "aws-sdk", "~> 1.38"
  spec.add_dependency "gli"
  spec.add_dependency "hashie"
  spec.add_dependency "highline"

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec", "3.0.0.beta2"
  spec.add_development_dependency "guard", "~> 2.5.0"
  spec.add_development_dependency "guard-rspec", "~> 4.2"
  spec.add_development_dependency "terminal-notifier-guard"
  spec.add_development_dependency "simplecov"
end
