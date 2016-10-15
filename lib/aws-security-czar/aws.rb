require 'aws-sdk'
require 'highline'

module AwsSecurityCzar
  module AwsClients
    extend self

    def build_client_methods
      services_with_clients.each do |service|
        define_singleton_method service.downcase do |options = {}|
          get_client Aws.const_get(service).const_get(:Client), options
        end
      end
      undef_method :build_client_methods
    end

    def clients
      @clients ||= {}
    end

    def sessions
      @sessions ||= {}
    end

    ### This module should only expose the actual clients. All supporting logic should be private.
    private

    def get_client(client, options)
      clients[client.to_s].each{ |c| return c[:client] if c[:options] == options } if clients[client.to_s]
      new_client(client, options)
    end

    def new_client(client, options)
      new_client = authenticated(client, options)
      clients[client.to_s] ||= []
      clients[client.to_s] << {options: options, client: new_client }
      new_client
    end

    def authenticated(client, options)
      Aws.config.update(region: GlobalConfig.region, profile: GlobalConfig.profile)
      Aws.config.update(Aws.config.merge(credentials: session_credentials)) if (!options[:profile] && GlobalConfig.mfa)
      options.merge(credentials: session_credentials(options[:profile])) if (options[:profile] && GlobalConfig.mfa)
      client.new(options)
    end

    def session_credentials(profile = nil)
      clear_session(profile) if session_is_expired?(profile)
      Aws::Credentials.new(
          session(profile).credentials.access_key_id,
          session(profile).credentials.secret_access_key,
          session(profile).credentials.session_token
      )
    end

    def session(profile = nil)
      sessions[profile.to_s] ||= Aws::STS::Client.new(profile: profile).get_session_token(
          { duration_seconds: GlobalConfig.mfa_duration || 900,
            serial_number: mfa_serial_number(profile),
            token_code: mfa_token(profile)
          }
      )
    end

    def clear_session(profile = nil)
      sessions.delete profile.to_s
    end

    def session_is_expired?(profile = nil)
      session(profile).credentials.expiration <= Time.now
    end

    def mfa_token(profile = nil)
      cli = HighLine.new
      cli.ask("Enter MFA Token for #{account_alias(profile)}:  ") { |q| q.validate = /^\d{6}$/ }
    end

    def mfa_serial_number(profile = nil)
      # Need to override the IAM client for this operation since we don't have an MFA session yet
      iam = Aws::IAM::Client.new(profile: profile)
      mfa_devices = iam.list_mfa_devices(user_name: iam.get_user.user.user_name).mfa_devices
      raise MfaNotConfigured, "MFA is not configured on your account! (Profile: #{profile}, IAM Org: #{account_alias(profile)})" unless mfa_devices.count > 0
      mfa_devices.first.serial_number
    end

    def account_alias(profile = nil)
      Aws::IAM::Client.new(profile: profile).list_account_aliases.account_aliases.first || "no alias"
    end

    def services_with_clients
      Aws.constants.select{ |c| Aws.const_get(c).public_methods.include?(:constants) && Aws.const_get(c).constants.include?(:Client) }
    end

    MfaNotConfigured = Class.new(StandardError)
  end

  AwsClients.build_client_methods
end
