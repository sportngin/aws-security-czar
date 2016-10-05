require 'spec_helper.rb'
require 'aws_security_czar'


module AwsSecurityCzar
  describe AwsClients do
    let(:environment) {double}

    before do
      GlobalConfig.region = 'us-east-1'
      allow(Aws::EC2::Client).to receive(:new).and_return(Aws::EC2::Client.new(stub_responses: true))
      allow(Aws::IAM::Client).to receive(:new).and_return(Aws::IAM::Client.new(stub_responses: true))
      allow(Aws::STS::Client).to receive(:new).and_return(Aws::STS::Client.new(stub_responses: true))
    end

    context ".ec2" do
      before do
        allow(GlobalConfig).to receive(:profile).and_return('default')
      end

      it "should use the region defined in GlobalConfig" do
        expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
        expect(Aws.config[:region]).to eql(GlobalConfig.region)
      end

      context "without mfa" do
        before do
          Aws.config.update(region: nil)
          AwsClients.remove_instance_variable(:@ec2) if AwsClients.instance_variable_defined?(:@ec2)
        end

        it "configures the SDK using the profile specifid by <environment>" do
          expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
          expect(Aws.config[:profile]).to eql(GlobalConfig.profile)
        end
      end

      context "with mfa" do
        before do
          Aws.config.update(region: nil)
          AwsClients.remove_instance_variable(:@ec2) if AwsClients.instance_variable_defined?(:@ec2)
          expect(GlobalConfig).to receive(:mfa).and_return(true)
          allow(AwsClients).to receive(:mfa_token).and_return('123456')
          mock_iam = Aws::IAM::Client.new(stub_responses: true)
          mock_iam.stub_responses(:list_mfa_devices, mfa_devices: [Aws::IAM::Types::MFADevice.new(user_name: 'test.user', serial_number: 'arn:aws:iam::123456789012:mfa/test.user', enable_date: Time.now())])
          expect(Aws::IAM::Client).to receive(:new).and_return(mock_iam)
        end

        it "configures the SDK using the profile specifid by <environment> and includes STS session credentials" do
          expect(AwsClients.ec2).to be_a(Aws::EC2::Client)
          expect(Aws.config[:profile]).to eql(GlobalConfig.profile)
          expect(Aws.config[:region]).to eql(GlobalConfig.region)
          expect(Aws.config[:credentials]).to be_a(Aws::Credentials)
        end
      end


    end

  end
end
