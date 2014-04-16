require 'yaml'

module Ec2SecurityCzar
  class SecurityGroup

    attr_accessor :api, :rules_config, :diff

    def initialize(api)
      @api = api
      load_rules
    end

    def update_rules
      if rules_config
        puts "Applying changes for #{api.name}:"
        rules_diff
        [:outbound, :inbound].each do |direction|
          diff[:additions][direction].each{ |rule| rule.authorize!(api) }
          diff[:deletions][direction].each{ |rule| rule.revoke!(api) }
        end
      else
        puts "No config file for #{api.name}, skipping..."
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

    private
    def load_rules
      if File.exists? config_filename
        @rules_config = YAML.load_file("config/#{api.name}.yml")
      end
    end

    def config_filename
      "config/#{api.name}.yml"
    end

    def rule_exists?(direction, current_rule)
      @diff[:additions][direction].reject!{ |rules| rules.equal?(current_rule) }
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
