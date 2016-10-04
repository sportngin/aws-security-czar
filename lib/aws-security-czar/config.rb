require 'yaml'
require 'hashie'

module AwsSecurityCzar
  module GlobalConfig
    extend self

    def config
      config_data.to_hash
    end

    def load(path)
      load_config(path)
      config
    end

    def config_data
      @config_data ||= Hashie::Mash.new
    end
    private :config_data

    def method_missing(method, args=false)
      config_data.send(method, args)
    end
    private :method_missing

    def load_config(file)
      raise MissingConfig, "Missing configuration file: #{file}  Run 'aws-security-czar help'" unless File.exist?(file)
      config_data.merge! YAML.load_file(file)
    end
    private :load_config
  end

  class ConfigInstance
    include GlobalConfig
  end

  MissingConfig = Class.new(StandardError)
end
