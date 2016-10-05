require 'spec_helper.rb'
require 'aws-security-czar/base'

module AwsSecurityCzar
  describe Base do
    let(:region) { 'us-east-1' }
    let(:ec2) { AwsClients.ec2 }
    let(:environment) {double}

    before do
      allow(GlobalConfig).to receive(:region).and_return('us-east-1')
      stub_const("SecurityGroup", double("Security Group"))
      allow(SecurityGroup).to receive(:update_security_groups) {[]}
    end

    context ".new" do
      subject { Base }

      it "configures the AWS sdk" do
        expect(AwsClients).to receive(:ec2)
        subject.new
      end
    end

    context "#update_security_groups" do
      let(:environment) { 'environment' }
      let(:environment_conf) { { environment => aws_conf } }

      before do
        subject.instance_variable_set("@environment", environment)
      end

      it "delegates to the SecurityGroup class" do
        expect(SecurityGroup).to receive(:update_security_groups).with(ec2, environment, region)
        subject.update_security_groups
      end
    end
  end
end
