require 'yaml'
require 'erb'
require 'hashie'

module Ec2SecurityCzar
  class SecurityGroupConfig < Hash
    include Hashie::Extensions::IndifferentAccess
  end

  class SecurityGroup

    attr_accessor :api, :rules_config, :diff

    def initialize(api, environment)
      @api = api
      @environment = environment
      load_rules
    end

    def update_rules
      if rules_config
        puts "================================================="
        puts "Applying changes for #{api.name}:"
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
          diff[:additions][direction].each{ |rule| rule.authorize!(api) }
        end
        puts "\n"
      else
        puts "No config file for #{api.name}, skipping...\n\n"
      end
    end

    def self.from_api(ec2)
      @security_groups = ec2.security_groups
    end

    def self.name_lookup(name)
      @security_group_hash ||= security_groups.inject({}) do |hash, security_group|
        hash[security_group.name] = security_group.id
        hash
      end
      @security_group_hash[name]
    end

    def self.config_security_groups
      Dir["config/*.yml"].reject!{|file| file == "config/aws_keys.yml"}.map do |file|
        File.basename(file,File.extname(file))
      end
    end

    def self.missing_security_groups
      config_security_groups - security_groups.map{|sg| sg[:name]}
    end

    private

    def self.security_groups
      @security_groups
    end
    private_class_method :security_groups

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

    def load_rules
      if File.exists? config_filename
        environment = @environment
        @rules_config = SecurityGroupConfig[YAML.load(ERB.new(File.read(config_filename)).result(binding))]
      end
    end

    def config_filename
      "config/#{api.name}.yml"
    end

    def rule_exists?(direction, current_rule)
      @diff[:additions][direction].reject!{ |rule| rule.equal?(current_rule) }
    end

    def current_rules(direction)
      api_rules = direction == :outbound ? api.egress_ip_permissions : api.ingress_ip_permissions
      Rule.rules_from_api(api_rules, direction)
    end

    def new_rules(direction)
      Rule.rules_from_config(rules_config, direction)
    end

  end

end
