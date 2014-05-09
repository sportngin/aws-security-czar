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
    let(:file) { double("Raw File") }
    let(:parsed_file) { double("Parsed File") }

    subject { SecurityGroup.new(api) }

    before do
      allow_any_instance_of(SecurityGroup).to receive(:config_filename).and_return(filename)
      allow(YAML).to receive(:load).with(parsed_file).and_return(rules_config)
      allow(ERB).to receive(:new).and_return(double(:result => parsed_file))
      allow(File).to receive(:read).and_return(double(:result => file))
      allow(File).to receive(:exists?).with(filename).and_return(true)
      allow(subject).to receive(:puts)
    end

    context "#update_rules" do
      let(:delete_inbound) { double("Inbound rule to be deleted") }
      let(:delete_outbound) { double("Outbound rule to be deleted") }
      let(:addition_inbound) { double("Inbound rule to be added") }
      let(:addition_outbound) { double("Outbound rule to be added") }

      before do
        allow(subject).to receive(:new_rules).with(:outbound).and_return([addition_outbound])
        allow(subject).to receive(:new_rules).with(:inbound).and_return([addition_inbound])
        allow(subject).to receive(:current_rules).with(:outbound).and_return([delete_outbound])
        allow(subject).to receive(:current_rules).with(:inbound).and_return([delete_inbound])
      end

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

    context ".name_lookup" do
      let(:security_group_name) { 'sec-group-name' }
      let(:security_group_id) { 'sec-group' }
      let(:security_groups) { [instance_double("AWS::EC2::SecurityGroup", name: security_group_name, id: security_group_id)] }
      it "returns the group id corresponding to the group name" do
        allow(SecurityGroup).to receive(:security_groups).and_return(security_groups)
        expect(SecurityGroup.name_lookup(security_group_name)).to equal(security_group_id)
      end
    end

    context ".from_api" do
      let(:ec2) { double }
      it "delegates to the ec2 object" do
        expect(ec2).to receive(:security_groups)
        SecurityGroup.from_api(ec2)
      end
    end

  end
end
