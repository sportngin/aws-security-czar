require 'spec_helper.rb'
require 'ec2-security-czar/base'

module Ec2SecurityCzar
  describe Base do
    let(:access_key){ 'aws-key' }
    let(:secret_access_key){ 'aws-secret-key' }
    let(:region) { 'us-east-1' }
    let(:aws_conf) { { access_key: access_key, secret_key: secret_access_key } }
    let(:ec2) { double }

    before do
      allow(YAML).to receive(:load_file).and_return(aws_conf)
      stub_const("AWS", double("AWS const"))
      stub_const("SecurityGroup", double("Security Group"))
      allow(AWS).to receive(:ec2).and_return(ec2)
      allow(AWS).to receive(:config)
    end

    context ".new" do
      subject { Base }

      it "handle's errors" do
        expect_any_instance_of(Base).to receive(:handle_error)
        allow(AWS).to receive(:config).and_raise(StandardError)
        subject.new
      end

      context "without mfa" do
        it "configures the AWS sdk" do
          expect(AWS).to receive(:config).with(
            hash_including(access_key_id: access_key, secret_access_key: secret_access_key, region: region)
          )
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
          allow(AWS).to receive(:config)
          expect_any_instance_of(Base).to receive(:mfa_auth).with(
            aws_conf,
            mfa_token
          )
          subject.new(mfa_token)
        end
      end
    end

    context "#update_rules" do
      let(:security_group) { double }
      it "calls update_rules on each Security Group" do
        allow(subject).to receive(:security_groups).and_return(1..3)
        expect(security_group).to receive(:update_rules).exactly(3).times
        expect(SecurityGroup).to receive(:new).exactly(3).times.with(any_args).and_return(security_group)
        subject.update_rules
      end

      it "handle's errors" do
        expect(subject).to receive(:handle_error)
        allow(subject).to receive(:security_groups).and_return(1..3)
        allow(security_group).to receive(:update_rules).exactly(2).times
        allow(security_group).to receive(:update_rules).once().and_raise(StandardError)
        allow(SecurityGroup).to receive(:new).exactly(3).times.with(any_args).and_return(security_group)
        subject.update_rules
      end
    end

    context "#security_groups" do
      it "delegates to the SecurityGroup class" do
        expect(SecurityGroup).to receive(:from_api).with(ec2)
        subject.security_groups
      end
    end
  end
end
