require 'aws-sdk'
require 'yaml'

module Ec2SecurityCzar
  class Base
    attr_accessor :ec2

    def initialize(mfa_token=nil)
      keys = YAML.load_file('config/aws_keys.yml')
      AWS.config(access_key_id: keys[:access_key], secret_access_key: keys[:secret_key], region: "us-east-1")
      if keys[:mfa_serial_number]
        @ec2 = mfa_auth(keys, mfa_token)
      else
        @ec2 = AWS.ec2
      end
    rescue Exception => e
      puts e.class
      puts e.message
      exit 1
    end

    def update_rules
      security_groups.each do |sg|
        security_group = SecurityGroup.new sg
        security_group.update_rules
      end
    end

    def security_groups
      ec2.security_groups
    end

    private
    def mfa_auth(keys, mfa_token)
      raise MFATokenMissing unless mfa_token
      sts = AWS::STS.new(access_key_id: keys[:access_key], secret_access_key: keys[:secret_key])
      session = sts.new_session(duration: 3600, serial_number: keys[:mfa_serial_number], token_code: mfa_token)
      AWS::EC2.new(session.credentials)
    rescue MFATokenMissing
      puts "MFA token is required as an argument!"
      exit 1
    rescue AWS::STS::Errors::AccessDenied
      puts "Multifactor Authentication failed."
      exit 1
    end
  end

  class MFATokenMissing < StandardError
  end
end
