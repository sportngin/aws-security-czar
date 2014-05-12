require 'aws-sdk'
require 'yaml'
require 'hashie'

module Ec2SecurityCzar
  class AwsConfig < Hash
    include Hashie::Extensions::IndifferentAccess
  end

  class Base
    attr_accessor :ec2

    def initialize(environment=nil, args={})
      raise MissingConfig.new("Missing aws_keys.yml config file") unless File.exists?(config_filename)
      @environment = environment
      load_config
      AWS.config(access_key_id: @config[:access_key], secret_access_key: @config[:secret_key], region: @config[:region])
      if @config[:mfa_serial_number]
        @ec2 = mfa_auth(args[:token])
      else
        @ec2 = AWS.ec2
      end
    end

    def update_rules
      security_groups.each do |sg|
        security_group = SecurityGroup.new(sg, @environment)
        security_group.update_rules
      end
    end

    def security_groups
      SecurityGroup.from_api(ec2)
    end

    def load_config
      return @config if @config
      @config = AwsConfig[YAML.load_file(config_filename)]
      @config = @config[@environment] if @environment
      @config[:region] ||= 'us-east-1'
      @config
    end

    private
    def mfa_auth(mfa_token)
      raise MFATokenMissing.new("MFA token is required as an argument!") unless mfa_token
      sts = AWS::STS.new(access_key_id: @config[:access_key], secret_access_key: @config[:secret_key])
      session = sts.new_session(duration: @config[:mfa_duration] || 900, serial_number: @config[:mfa_serial_number], token_code: mfa_token)
      AWS::EC2.new(session.credentials)
    end

    def config_filename
      'config/aws_keys.yml'
    end
  end

  MFATokenMissing = Class.new(StandardError)
  MissingConfig = Class.new(StandardError)
end
