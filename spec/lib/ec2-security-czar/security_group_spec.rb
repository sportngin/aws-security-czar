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
    let(:parsed_file) { double("Parsed File") }
    let(:environment) { 'environment' }

    subject { SecurityGroup.new(api, environment) }

    before do
      allow_any_instance_of(SecurityGroup).to receive(:config_filename).and_return(filename)
      allow(File).to receive(:read).and_return(file)
      allow(File).to receive(:exists?).with(filename).and_return(true)
      allow(subject).to receive(:puts)
    end

    context "#update_rules" do
      let(:delete_inbound) { double("Inbound rule to be deleted") }
      let(:delete_outbound) { double("Outbound rule to be deleted") }
      let(:addition_inbound) { double("Inbound rule to be added") }
      let(:addition_outbound) { double("Outbound rule to be added") }

      before do
        allow(ERB).to receive(:new).and_return(double(:result => parsed_file))
        allow(YAML).to receive(:load).with(parsed_file).and_return(rules_config)
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

    context "#load_rules" do
      let(:environment) { 'parsed' }
      let(:file) { "-- \n<%= environment %> \n" }

      it "passes the environment into the erb rendering" do
        expect(subject.send(:load_rules)).to match(environment)
      end
    end

  end
end
