require 'aws-sdk'
require 'yaml'
require 'hashie'

module AwsSecurityCzar
  class AwsConfig < Hash
    include Hashie::Extensions::IndifferentAccess
  end

  class Base
    attr_accessor :ec2

    def initialize(environment=nil, args={})
      @environment = environment
      @ec2 = AwsClients.ec2
    end

    def update_security_groups
      SecurityGroup.update_security_groups(ec2, @environment, GlobalConfig.region)
    end
  end

end
