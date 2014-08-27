require 'yaml'
require 'erb'
require 'hashie'

module Ec2SecurityCzar
  class SecurityGroupConfig < Hash
    include Hashie::Extensions::IndifferentAccess
  end

  class SecurityGroup

    attr_accessor :name, :rules_config, :diff

    def initialize(name, environment)
      @name = name
      @environment = environment
      load_rules
    end

    # Public: Creates missing security groups, updates all security groups
    # 
    # ec2: ec2 instance created in base.rb
    # environment: environment passed in from commandline
    def self.update_security_groups(ec2, environment)
      @ec2 = ec2
      create_missing_security_groups(environment)
      update_rules
    end

    def self.update_rules
      security_groups.each do |sg|
        security_group = SecurityGroup.new(sg.name, @environment)
        security_group.update_rules
      end
    end

    # Public: Creates a hash mapping security_group.name to security_group, or looks up security_group by name
    # 
    # name: the name of the security group to lookup 
    #
    # Returns - SecurityGroup object 
    def self.name_lookup(name)
      @security_group_hash ||= security_groups.inject({}) do |hash, security_group|
        hash[security_group.name] = security_group
        hash
      end
      @security_group_hash[name]
    end

    # Private: Gets all security groups from AWS
    #
    # Returns - SecurityGroupCollection 
    def self.from_aws
      @security_groups = ec2.security_groups
    end

    # Private: Gets all the security groups with YAML files
    #
    # Returns - Array of all security group names
    def self.config_security_groups
      Dir["config/*.yml"].reject!{|file| file == "config/aws_keys.yml"}.map do |file|
        File.basename(file,File.extname(file))
      end
    end
    private_class_method :config_security_groups

    # Public: Finds security groups with YAML files not on AWS
    #
    # Returns - Array of all security group names not on AWS
    def self.missing_security_groups
      config_security_groups - from_aws.map(&:name)
    end
    private_class_method :missing_security_groups

    # Public: Creates missing security groups
    #
    # Returns - nil
    def self.create_missing_security_groups(environment)
      missing_security_groups.each do |name|
        security_group = SecurityGroup.new(name, environment)
        config = security_group.rules_config
        ec2.security_groups.create(name, vpc: config[:vpc], description: config[:description]) 
      end
    end
    private_class_method :create_missing_security_groups

    # Private: @security_groups accessor
    #
    # Returns - @security_groups
    def self.security_groups
      @security_groups
    end
    private_class_method :security_groups

    # Private: @ec2 accessor
    #
    # Returns - @ec2
    def self.ec2
      @ec2 
    end
    private_class_method :ec2


    def update_rules
      if rules_config
        puts "================================================="
        puts "Applying changes for #{name}:"
        puts "================================================="

        # Apply deletions first
        rules_diff
        [:outbound, :inbound].each do |direction|
          diff[:deletions][direction].each{ |rule| rule.revoke! }
        end

        # Re-calculate the diff after performing deletions to make sure we add
        # back any that got removed because of the way AWS groups rules together.
        rules_diff
        [:outbound, :inbound].each do |direction|
          diff[:additions][direction].each{ |rule| rule.authorize!(self.class.name_lookup(name)) }
        end
        puts "\n"
      else
        puts "No config file for #{name}, skipping...\n\n"
      end
    end

    def rules_diff
      @diff = { deletions: {}, additions: {} }

      [:outbound, :inbound].each do |direction|
        @diff[:deletions][direction] = []
        @diff[:additions][direction] = new_rules(direction)

        current_rules(direction).each do |current_rule|
          unless rule_exists?(direction, current_rule)
            @diff[:deletions][direction] << current_rule
          end
        end
      end
      diff
    end
    private :rules_diff

    def load_rules
      if File.exists? config_filename
        environment = @environment
        @rules_config = SecurityGroupConfig[YAML.load(ERB.new(File.read(config_filename)).result(binding))]
      end
    end

    def config_filename
      "config/#{name}.yml"
    end
    private :config_filename

    def rule_exists?(direction, current_rule)
      @diff[:additions][direction].reject!{ |rule| rule.equal?(current_rule) }
    end
    private :config_filename

    def current_rules(direction)
      security_group = self.class.name_lookup(name)
      aws_security_group_rules = direction == :outbound ? security_group.egress_ip_permissions : security_group.ingress_ip_permissions
      Rule.rules_from_api(aws_security_group_rules, direction)
    end
    private :current_rules

    def new_rules(direction)
      Rule.rules_from_config(rules_config, direction)
    end
    private :new_rules

  end
end
