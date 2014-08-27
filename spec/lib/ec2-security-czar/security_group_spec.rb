require 'spec_helper.rb'
require 'ec2-security-czar/security_group'

module Ec2SecurityCzar
  describe SecurityGroup do
    let(:api) { double("API", name: 'test') }
    let(:outbound_rule) {
      {
        zone: "Test Outbound",
        justification: "Test outbound justification",
        groups: [ 'test-outbound-group-id' ],
        protocol: :udp,
        port_range: '666'
      }
    }
    let(:inbound_rule) {
      {
        zone: "Test Inbound",
        justification: "Test inbound justification",
        groups: [ 'test-inbound-group-id' ],
        protocol: :tcp,
        port_range: '999'
      }
    }

    let(:rules_config) { { outbound: [outbound_rule], inbound: [inbound_rule] } }
    let(:filename) { 'the/config/file' }
    let(:file) { "Raw File" }
    let(:parsed_file) { { derp: :herp } }
    let(:environment) { 'environment' }


    before do
      allow(File).to receive(:read).and_return(file)
      allow_any_instance_of(SecurityGroup).to receive(:config_filename).and_return(filename)
      allow(File).to receive(:exists?).with(filename).and_return(true)
    end

    context "#update_rules" do
      let(:delete_inbound) { double("Inbound rule to be deleted") }
      let(:delete_outbound) { double("Outbound rule to be deleted") }
      let(:addition_inbound) { double("Inbound rule to be added") }
      let(:addition_outbound) { double("Outbound rule to be added") }

      before do
        allow(ERB).to receive(:new).and_return(double(:result => parsed_file))
        allow(YAML).to receive(:load).and_return(parsed_file)
        allow(subject).to receive(:new_rules).with(:outbound).and_return([addition_outbound])
        allow(subject).to receive(:new_rules).with(:inbound).and_return([addition_inbound])
        allow(subject).to receive(:current_rules).with(:outbound).and_return([delete_outbound])
        allow(subject).to receive(:current_rules).with(:inbound).and_return([delete_inbound])
        allow(subject).to receive(:puts)
        allow(SecurityGroup).to receive(:name_lookup) {api}
      end

      subject { SecurityGroup.new(api, environment) }

      it "revokes rules that have been deleted" do
        allow(addition_outbound).to receive(:authorize!)
        allow(addition_inbound).to receive(:authorize!)
        expect(delete_inbound).to receive(:revoke!)
        expect(delete_outbound).to receive(:revoke!)
        subject.update_rules
      end

      it "authorizes rules that have been added" do
        allow(delete_inbound).to receive(:revoke!)
        allow(delete_outbound).to receive(:revoke!)
        expect(addition_outbound).to receive(:authorize!).with(api)
        expect(addition_inbound).to receive(:authorize!).with(api)
        subject.update_rules
      end
    end

    context "#load_rules" do
      let(:environment) { 'parsed' }
      let(:erb_file) { "--- \nenvironment: <%= environment %> \n" }

      before do
        allow(File).to receive(:read).with(filename).and_return(erb_file)
      end

      subject { SecurityGroup.new(api, environment) }

      it "passes the environment into the erb rendering" do
        expect(SecurityGroupConfig).to receive(:[]).at_least(:once).with(hash_including('environment' => 'parsed'))
        subject.send(:load_rules)
      end
    end

    context "#config_security_groups" do
      let(:environment) { 'parsed' }
      let(:erb_file) { "--- \nenvironment: <%= environment %> \n" }

      before do
        allow(File).to receive(:read).with(filename).and_return(erb_file)
      end

      it "returns an array of file names with out the extension" do
        allow(Dir).to receive(:[]).and_return(["config/aws_keys.yml", "config/foo.yml", "config/bar.yml"])
        expect(SecurityGroup.send(:config_security_groups)).to eq(["foo","bar"])
      end
    end

    context "#missing_security_groups" do
      let(:environment) { 'parsed' }
      let(:erb_file) { "--- \nenvironment: <%= environment %> \n" }
      let(:security_group_1) { double }
      let(:security_group_2) { double }

      before do
        allow(File).to receive(:read).with(filename).and_return(erb_file)
        allow(SecurityGroup).to receive(:config_security_groups).and_return(["foo","bar"])
        allow(security_group_1).to receive(:name).and_return("foo")
        allow(security_group_2).to receive(:name).and_return("bar")
      end

      it "returns empty if config_security_groups is the same as security_groups" do
        allow(SecurityGroup).to receive(:from_aws).and_return([security_group_1, security_group_2])
        expect(SecurityGroup.send(:missing_security_groups)).to eq([])
      end

      it "returns groups in config_security_groups not in security_groups" do
        allow(SecurityGroup).to receive(:from_aws).and_return([security_group_2])
        expect(SecurityGroup.send(:missing_security_groups)).to eq(["foo"])
      end
    end

    context ".name_lookup" do
      let(:security_group_name) { 'sec-group-name' }
      let(:security_group_id) { 'sec-group' }
      let(:security_group) { instance_double("AWS::EC2::SecurityGroup", name: security_group_name, id: security_group_id) }
      let(:security_groups) { [security_group] }
      it "returns the group id corresponding to the group name" do
        allow(SecurityGroup).to receive(:security_groups).and_return(security_groups)
        expect(SecurityGroup.name_lookup(security_group_name)).to equal(security_group)
      end
    end

    context ".from_aws" do
      let(:ec2) { double }
      before do
        allow(SecurityGroup).to receive(:security_groups) {nil}
        allow(SecurityGroup).to receive(:ec2) {ec2}
      end
      it "delegates to the ec2 object" do
        expect(ec2).to receive(:security_groups)
        SecurityGroup.from_aws
      end
    end

    context ".create_missing_security_groups" do
      let(:ec2) { double }
      let(:security_groups) { double }
      let(:environment) { 'parsed' }
      let(:security_group_name) {'sec-group-name'}
      let(:security_group) { double }

      before do
        allow(SecurityGroup).to receive(:ec2) {ec2}
        allow(ec2).to receive(:security_groups) {security_groups}
        allow(SecurityGroup).to receive(:missing_security_groups).and_return(['sec-group-name'])
        allow(SecurityGroup).to receive(:new).with(security_group_name,environment).and_return(security_group)
        allow(security_group).to receive(:rules_config).and_return({vpc: "vpc"})
      end

      it "create missing security groups" do
        expect(security_groups).to receive(:create)
        SecurityGroup.send(:create_missing_security_groups, environment)
      end
    end

    context ".update_rules" do
      let(:ec2) { double }
      let(:security_group) { double }
      let(:security_groups) { [security_group] }

      before do
        allow(SecurityGroup).to receive(:security_groups) {security_groups}
        allow(SecurityGroup).to receive(:new).with('sec-group-name',nil).and_return(security_group)
        allow(security_group).to receive(:name) {'sec-group-name'}
      end

      it "calls #update_rules" do
        expect(security_group).to receive(:update_rules)
        SecurityGroup.send(:update_rules)
      end
    end

    context ".udpate_security_groups" do
      let(:ec2) { double }
      let(:environment) { 'test' }
      it "calls everything it's supposed to" do
        expect(SecurityGroup).to receive(:create_missing_security_groups)
        expect(SecurityGroup).to receive(:update_rules)
        SecurityGroup.send(:update_security_groups, ec2, environment)
      end
    end
  end
end
