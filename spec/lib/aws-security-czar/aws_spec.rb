require 'spec_helper.rb'
require 'aws_security_czar'

module AwsSecurityCzar
  describe AwsClients do
    let(:environment) {double}
    let(:reset_aws_config) { Aws.config.keys.each{ |k| Aws.config.delete k } }
    let(:reset_ec2_clients) { AwsClients.clients.delete "Aws::EC2::Client" }
    let(:reset_aws_sessions) { AwsClients.sessions.keys.each{ |k| AwsClients.sessions.delete k } }
    let(:mfa_devices) { [Aws::IAM::Types::MFADevice.new(user_name: 'test.user', serial_number: 'arn:aws:iam::123456789012:mfa/test.user', enable_date: Time.now())] }
    let(:supported_services) { Aws.constants.select{ |c| Aws.const_get(c).public_methods.include?(:constants) && Aws.const_get(c).constants.include?(:Client) } }

    before do
      GlobalConfig.region = 'us-east-1'
      GlobalConfig.profile = 'default'
      allow(Aws::EC2::Client).to receive(:new).and_return(Aws::EC2::Client.new(stub_responses: true))
      allow(Aws::IAM::Client).to receive(:new).and_return(Aws::IAM::Client.new(stub_responses: true))
      allow(Aws::STS::Client).to receive(:new).and_return(Aws::STS::Client.new(stub_responses: true))
      allow(AwsClients).to receive(:mfa_token).and_return('123456')
    end

    context "client methods" do
      it "should be created for all supported AWS services" do
        supported_services.each do |service|
          expect(AwsClients).to respond_to service.downcase
        end
      end

      it "should not allow the method constructor to be called after the module is loaded" do
        expect(AwsClients).not_to respond_to :build_client_methods
      end
    end

    context ".ec2" do
      before do
        reset_aws_config
        reset_ec2_clients
      end
      it "should use the region defined in GlobalConfig" do
        expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
        expect(Aws.config[:region]).to eql(GlobalConfig.region)
        expect(Aws.config[:profile]).to eql(GlobalConfig.profile)
      end

      context "always" do
        before do
          reset_aws_config
          reset_ec2_clients
        end

        it "should reuse a client once it is built" do
          expect(Aws::EC2::Client).to receive(:new).once
          expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
          expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
        end

        it "should build a new client when given a unique options hash" do
          expect(Aws::EC2::Client).to receive(:new).twice
          expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
          expect(AwsClients.ec2(region: 'us-west-1')).to be_a(Aws::EC2::Client)
        end

        it "should reuse the correct client when an identical options hash is found" do
          expect(Aws::EC2::Client).to receive(:new).exactly(3).times
          expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
          expect(AwsClients.ec2(region: 'us-west-1')).to be_a(Aws::EC2::Client)
          expect(AwsClients.ec2(region: 'us-west-2')).to be_a(Aws::EC2::Client)
          expect(AwsClients.ec2(region: 'us-west-1')).to be_a(Aws::EC2::Client)
          expect(AwsClients.ec2(region: 'us-west-2')).to be_a(Aws::EC2::Client)
        end
      end

      context "without mfa" do
        before do
          reset_aws_config
          reset_ec2_clients
        end

        it "configures the SDK using the profile specified by <environment> and does not set explicit credentials" do
          expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
          expect(Aws.config[:profile]).to eql(GlobalConfig.profile)
          expect(Aws.config[:region]).to eql(GlobalConfig.region)
          expect(Aws.config).not_to include(:credentials)
        end
      end

      context "with properly configured mfa" do
        before do
          reset_aws_config
          reset_ec2_clients
          reset_aws_sessions
          allow(GlobalConfig).to receive(:mfa).and_return(true)
          mock_iam = Aws::IAM::Client.new(stub_responses: true)
          mock_iam.stub_responses(:list_mfa_devices, mfa_devices: mfa_devices)
          allow(Aws::IAM::Client).to receive(:new).and_return(mock_iam)
        end

        it "configures the SDK using the profile specified by <environment> and includes STS session credentials" do
          expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
          expect(Aws.config[:profile]).to eql(GlobalConfig.profile)
          expect(Aws.config[:region]).to eql(GlobalConfig.region)
          expect(Aws.config[:credentials]).to be_a(Aws::Credentials)
        end

        it "should create a session for each profile used with MFA" do
          expect(GlobalConfig).to receive(:mfa).and_return(true)
          expect(AwsClients).to receive(:mfa_token).and_return('123456')
          expect(AwsClients.ec2(profile: 'test1')).to be_a(Aws::EC2::Client)
          expect(AwsClients.ec2(profile: 'test2')).to be_a(Aws::EC2::Client)
          expect(AwsClients.ec2(profile: 'test1', region: 'us-west-2')).to be_a(Aws::EC2::Client)
          expect(AwsClients.sessions.count).to eql(2)
        end

      end

      context "called with MFA option and MFA not emabled on the AWS account" do
        before do
          reset_aws_config
          reset_ec2_clients
          expect(GlobalConfig).to receive(:mfa).and_return(true)
          allow(AwsClients).to receive(:mfa_token).and_return('123456')
        end

        it "raises an error" do
          expect{AwsClients.ec2}.to raise_error(AwsClients::MfaNotConfigured)
        end
      end
    end

  end
end
