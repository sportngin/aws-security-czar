require 'highline/import'

module AwsSecurityCzar
  class Rule

    attr_accessor :protocol, :port_range, :ip, :group, :egress

    def initialize(options)
      @egress = options[:direction] == :outbound
      @ip = options[:ip_range]
      @group = group_id(options[:group])
      @protocol = options[:protocol] || :tcp
      @port_range = options[:port_range] || (0..65535)
      @api_object = options[:api_object]
    end

    def equal?(rule)
      rule.protocol.to_s == protocol.to_s &&
      Array(rule.port_range) == Array(port_range) &&
      rule.ip == ip &&
      rule.group == group &&
      rule.egress == egress
    end

    def authorize!(security_group_api)
      sources = ip.nil? ? { group_id: group } : ip
      if egress
        security_group_api.authorize_egress(sources, protocol: protocol, ports: port_range)
      else
        security_group_api.authorize_ingress(protocol, port_range, sources)
      end
      say "<%= color('Authorized - #{pretty_print}', :green) %>"
    rescue StandardError => e
      say "<%= color('#{e.class} - #{e.message}', :red) %>"
      say "<%= color('#{pretty_print}', :red) %>"
    end

    def revoke!
      @api_object.revoke
      say "<%= color('Revoked - #{pretty_print}', :cyan) %>"
    rescue StandardError => e
      say "<%= color('#{e.class} - #{e.message}', :red) %>"
      say "<%= color('#{pretty_print}', :red) %>"
    end

    def group_id(group)
      if group.is_a? Hash
        group[:group_id] || SecurityGroup.lookup(group[:group_name]).id
      else
        group
      end
    end

    def self.rules_from_api(api_rules, direction)
      rules = []
      Array(api_rules).map do |api_rule|
        rules << api_rule.ip_ranges.map do |ip|
          Rule.new(ip_range: ip, port_range: api_rule.port_range, protocol: api_rule.protocol, direction: direction, api_object: api_rule)
        end
        rules << api_rule.groups.map do |group|
          Rule.new(group: group.id, port_range: api_rule.port_range, protocol: api_rule.protocol, direction: direction, api_object: api_rule)
        end
      end
      rules.flatten
    end

    def self.rules_from_config(config, direction)
      rules = []
      Array(config[direction]).map do |zone|
        rules << Array(zone[:ip_ranges]).map do |ip|
          Rule.new(ip_range: ip, port_range: zone[:port_range], protocol: zone[:protocol], direction: direction)
        end
        rules << Array(zone[:groups]).map do |group|
          Rule.new(group: group, port_range: zone[:port_range], protocol: zone[:protocol], direction: direction)
        end
      end
      rules.flatten
    end

    def pretty_print
      direction = egress ? "Outbound" : "Inbound"
      ip_or_group = ip ? ip : SecurityGroup.lookup(group).name
      port = port_range.is_a?(Range) ? "ports #{port_range}" : "port #{port_range}"
      "#{direction} traffic on #{port} for #{ip_or_group} using #{protocol}"
    end
  end
end
