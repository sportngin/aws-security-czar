module Ec2SecurityCzar
  class Rule

    attr_accessor :protocol, :port_range, :ip, :egress

    def initialize(options)
      @egress = options[:direction] == :outbound
      @ip = options[:ip_ranges]
      @protocol = options[:protocol] || :tcp
      @port_range = options[:port_range] || (0..65535)
    end

    def equal?(rule)
      rule.protocol.to_s == protocol.to_s &&
      Array(rule.port_range) == Array(port_range) &&
      rule.ip == ip &&
      rule.egress == egress
    end

    def authorize!(api)
      if egress
        api.authorize_egress(ip, protocol: protocol, ports: port_range)
      else
        api.authorize_ingress(protocol, port_range, ip)
      end
      puts "Authorized: #{inspect}"
    rescue StandardError => e
      puts "#{e.class} - #{e.message}"
      puts inspect
    end

    def revoke!(api)
      if egress
        api.revoke_egress(ip)
      else
        api.revoke_ingress(protocol, port_range, ip)
      end
      puts "Revoked: #{inspect}"
    rescue StandardError => e
      puts "#{e.class} - #{e.message}"
      puts inspect
    end

    def self.rules_from_api(api_rules, direction)
      Array(api_rules).map do |api_rule|
        api_rule.ip_ranges.map do |ip|
          Rule.new(ip_ranges: ip, port_range: api_rule.port_range, protocol: api_rule.protocol, direction: direction)
        end
      end.flatten
    end

    def self.rules_from_config(rules_config, direction)
      Array(rules_config[direction]).map do |zone|
        zone[:ip_ranges].map do |ip|
          Rule.new(ip_ranges: ip, port_range: zone[:port_range], protocol: zone[:protocol], direction: direction)
        end
      end.flatten
    end

  end
end
