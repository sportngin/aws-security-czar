require 'aws-sdk'
require 'yaml'

module Ec2SecurityCzar
  class Base
    attr_accessor :ec2

    def initialize
      keys = YAML.load_file('config/aws_keys.yml')
      AWS.config(access_key_id: keys[:access_key], secret_access_key: keys[:secret_key], region: "us-east-1")
      @ec2 = AWS.ec2
    end

    def update_rules
      security_groups.each do |sg|
        security_group = SecurityGroup.new sg
        security_group.update_rules
      end
    end

    def security_groups
      ec2.security_groups.select{|sg| sg.name.match(security_group_matcher) }
    end

    private
    def security_group_matcher
      /guardhouse-.*/
    end
  end
end
