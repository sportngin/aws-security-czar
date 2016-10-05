require 'aws-sdk'
require 'highline'

module AwsSecurityCzar
  module AwsClients
    extend self

    def ec2(options = {})
      @ec2 ||= authenticated Aws::EC2::Client, options
    end

    def iam(options = {})
      @iam ||= authenticated Aws::IAM::Client, options
    end

    ### This module should only expose the actual clients. All supporting logic should be private.
    private

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
      iam.list_mfa_devices(user_name: iam.get_user.user.user_name)
          .mfa_devices
          .first
          .serial_number
    end

    def account_alias
      @account_alias ||= Aws::IAM::Client.new.list_account_aliases.account_aliases.first
    end

  end
end
