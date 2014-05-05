module Ec2SecurityCzar
  class Rule

    attr_accessor :protocol, :port_range, :ip, :group, :egress

    def initialize(options)
      @egress = options[:direction] == :outbound
      @ip = options[:ip_range]
      @group = options[:group]
      @protocol = options[:protocol] || :tcp
      @port_range = options[:port_range] || (0..65535)
      @api_object = options[:api_object]
    end

    def equal?(rule)
      rule.protocol.to_s == protocol.to_s &&
      Array(rule.port_range) == Array(port_range) &&
      rule.ip == ip &&
      rule.egress == egress
    end

    def to_s
      inspect
    end

    def authorize!(api)
      if egress
        api.authorize_egress((ip || group), protocol: protocol, ports: port_range)
      else
        api.authorize_ingress(protocol, port_range, (ip || group))
      end
      puts "Authorized: #{to_s}"
    rescue StandardError => e
      puts "#{e.class} - #{e.message}"
      puts to_s
    end

    def revoke!(api)
      @api_object.revoke
      puts "Revoked: #{to_s}"
    rescue StandardError => e
      puts "#{e.class} - #{e.message}"
      puts to_s
    end

    def self.rules_from_api(api_rules, direction)
      rules = []
      Array(api_rules).map do |api_rule|
        rules << api_rule.ip_ranges.map do |ip|
          Rule.new(ip_range: ip, port_range: api_rule.port_range, protocol: api_rule.protocol, direction: direction, api_object: api_rule)
        end
        rules << api_rule.groups.map do |group|
          Rule.new(groups: group.id, port_range: api_rule.port_range, protocol: api_rule.protocol, direction: direction, api_object: api_rule)
        end
      end
      rules.flatten
    end

    def self.rules_from_config(rules_config, direction)
      rules = []
      Array(rules_config[direction]).map do |zone|
        rules << Array(zone[:ip_ranges]).map do |ip|
          Rule.new(ip_range: ip, port_range: zone[:port_range], protocol: zone[:protocol], direction: direction)
        end
        rules << Array(zone[:groups]).map do |group|
          Rule.new(group: group, port_range: zone[:port_range], protocol: zone[:protocol], direction: direction)
        end
      end
      rules.flatten
    end

  end
end
