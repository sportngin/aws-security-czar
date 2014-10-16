require 'spec_helper.rb'
require 'ec2-security-czar/base'

module Ec2SecurityCzar
  describe Base do
    let(:access_key){ 'aws-key' }
    let(:secret_access_key){ 'aws-secret-key' }
    let(:region) { 'us-east-1' }
    let(:aws_conf) { { access_key: access_key, secret_key: secret_access_key } }
    let(:ec2) { double }
    let(:environment) {double}

    before do
      allow(File).to receive(:exists?).with('config/aws_keys.yml').and_return(true)
      allow(YAML).to receive(:load_file).and_return(aws_conf)
      stub_const("AWS", double("AWS const"))
      stub_const("SecurityGroup", double("Security Group"))
      allow(AWS).to receive(:ec2).and_return(ec2)
      allow(AWS).to receive(:config)
      allow(SecurityGroup).to receive(:update_security_groups) {[]}
    end

    context ".new" do
      subject { Base }

      context "without mfa" do
        it "configures the AWS sdk" do
          expect(AWS).to receive(:config).with(
            hash_including(access_key_id: access_key, secret_access_key: secret_access_key, region: region)
          )
          allow(YAML).to receive(:load_file).with('config/aws_keys.yml').and_return(aws_conf)
          subject.new
        end
      end

      context "with mfa" do
        let(:mfa_token) { '12345' }
        let(:mfa_serial_number) { 'aws-mfa-serial' }
        let(:aws_conf) { { access_key: access_key, secret_key: secret_access_key, mfa_serial_number: mfa_serial_number } }

        it "configures the AWS sdk" do
          allow_any_instance_of(Base).to receive(:mfa_auth)
          expect(AWS).to receive(:config).with(
            hash_including(access_key_id: access_key, secret_access_key: secret_access_key, region: region)
          )
          subject.new
        end
        it "runs mfa auth" do
          expect_any_instance_of(Base).to receive(:mfa_auth).with(mfa_token)
          subject.new(nil, token: mfa_token)
        end
      end
    end

    context "#load_config" do
      subject { Base }
      context "no environment is set" do
        it "loads the config for the default environment" do
          expect(aws_conf).to_not receive(:[]).with(nil)
          subject.new
        end
      end
      context "environment is set" do
        let(:environment) { 'environment' }
        let(:environment_conf) { { environment => aws_conf } }

        before do
          allow(YAML).to receive(:load_file).with("config/aws_keys.yml").and_return(environment_conf)
        end

        it "loads the config for the passed environment" do
          expect(AwsConfig).to receive(:[]).with(environment_conf).and_return(environment_conf)
          expect(environment_conf).to receive(:[]).with(environment).and_return(aws_conf)
          subject.new(environment)
        end
      end
    end

    context "#update_security_groups" do
      let(:environment) { 'environment' }
      let(:environment_conf) { { environment => aws_conf } }

      before do
        subject.instance_variable_set("@environment", environment)
        allow(YAML).to receive(:load_file).with("config/aws_keys.yml").and_return(environment_conf)
      end

      it "delegates to the SecurityGroup class" do
        expect(SecurityGroup).to receive(:update_security_groups).with(ec2, environment, region)
        subject.update_security_groups
      end
    end
  end
end
