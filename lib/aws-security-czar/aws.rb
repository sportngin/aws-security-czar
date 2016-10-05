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
    end

    def clients
      @clients ||= {}
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
      Aws.config.update(Aws.config.merge(credentials: session_credentials)) if GlobalConfig.mfa
      client.new(options)
    end

    def session_credentials
      clear_session if session_is_expired?

      @session_credentials ||= Aws::Credentials.new(
          session.credentials.access_key_id,
          session.credentials.secret_access_key,
          session.credentials.session_token
      )
    end

    def session
      @session ||= Aws::STS::Client.new.get_session_token(
          { duration_seconds: GlobalConfig.mfa_duration || 900,
            serial_number: mfa_serial_number,
            token_code: mfa_token
          }
      )
    end

    def clear_session
      @session, @session_credentials = nil, nil
    end

    def session_is_expired?
      session.credentials.expiration <= Time.now
    end

    def mfa_token
      cli = HighLine.new
      cli.ask("Enter MFA Token for #{account_alias}:  ") { |q| q.validate = /^\d{6}$/ }
    end

    def mfa_serial_number
      # Need to override the IAM client for this operation since we don't have an MFA session yet
      iam = Aws::IAM::Client.new
      mfa_devices = iam.list_mfa_devices(user_name: iam.get_user.user.user_name).mfa_devices
      raise MfaNotConfigured, "MFA is not configured on your account! (Profile: #{GlobalConfig.profile}, IAM Org: #{account_alias})" unless mfa_devices.count > 0
      mfa_devices.first.serial_number
    end

    def account_alias
      Aws::IAM::Client.new.list_account_aliases.account_aliases.first || "no alias"
    end

    def services_with_clients
      Aws.constants.select{ |c| Aws.const_get(c).public_methods.include?(:constants) && Aws.const_get(c).constants.include?(:Client) }
    end

    MfaNotConfigured = Class.new(StandardError)
  end

  AwsClients.build_client_methods
end
