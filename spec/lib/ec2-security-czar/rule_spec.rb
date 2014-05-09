require 'spec_helper.rb'
require 'ec2-security-czar/rule'
require 'ec2-security-czar/security_group'

module Ec2SecurityCzar
  describe Rule do
    let(:direction) { :outbound }
    let(:ip_range) { '0.0.0.0/0' }
    let(:group) { { group_id: 'sec-group' } }
    let(:protocol) { :tcp }
    let(:port_range) { '666' }
    let(:api_object) { double }
    let(:options) {
      {
        direction: direction,
        ip_range: ip_range,
        protocol: protocol,
        port_range: port_range,
        api_object: api_object,
      }
    }

    before do
      allow(subject).to receive(:puts)
    end

    subject { Rule.new(options) }

    context "#equal?" do
      it "returns true if all options are equal" do
        expect(subject.equal?(subject.dup)).to be_truthy
      end

      it "returns false if all options are not equal" do
        bogus_rule = Rule.new(options.merge(ip_range: '1.1.1.1/32'))
        expect(subject.equal?(bogus_rule)).to be_falsey
      end

      context "rule with group name to a group id" do
        let(:group_name) { 'sec-group-name' }
        let(:options) {
          {
            direction: direction,
            group: group,
            protocol: protocol,
            port_range: port_range,
            api_object: api_object,
          }
        }

        it "returns true if the group ids are the same" do
          allow(SecurityGroup).to receive(:name_lookup).with(group_name).and_return(group[:group_id])
          equivalent_rule = Rule.new(options.merge(group: { group_name: group_name }))
          expect(subject.equal?(equivalent_rule)).to be_truthy
        end
      end
    end

    context "#authorize!" do
      let(:security_group_api) { double("Security Group API") }
      context "outbound rule" do
        let(:direction) { :outbound }
        it "authorizes an egress rule for aws" do
          expect(security_group_api).to receive(:authorize_egress).with(ip_range, hash_including(protocol: protocol, ports: port_range))
          subject.authorize!(security_group_api)
        end

        it "does not authorize an ingress rule for aws" do
          allow(security_group_api).to receive(:authorize_egress)
          expect(security_group_api).to_not receive(:authorize_ingress)
          subject.authorize!(security_group_api)
        end
      end

      context "inbound rule" do
        let(:direction) { :inbound }
        it "authorizes an ingress rule for aws" do
          expect(security_group_api).to receive(:authorize_ingress).with(protocol, port_range, ip_range)
          subject.authorize!(security_group_api)
        end

        it "does not authorize an egress rule for aws" do
          allow(security_group_api).to receive(:authorize_ingress)
          expect(security_group_api).to_not receive(:authorize_egress)
          subject.authorize!(security_group_api)
        end
      end

      context "group rule" do
        let(:direction) { :inbound }
        let(:group_id) { 'sec-group' }
        let(:options) {
          {
            direction: direction,
            group: { group_id: group_id },
            protocol: protocol,
            port_range: port_range,
            api_object: api_object,
          }
        }

        it "passes the group_id as a hash" do
          expect(security_group_api).to receive(:authorize_ingress).with(
            protocol, port_range, { group_id: group_id }
          )
          subject.authorize!(security_group_api)
        end
      end

      it "rescues an api error" do
        allow(security_group_api).to receive(:authorize_egress).and_raise(StandardError)
        expect(subject).to receive(:puts).twice
        expect { subject.authorize!(security_group_api) }.to_not raise_error
      end
    end

    context "#revoke!" do
      it "calls revoke on it's api object" do
        expect(api_object).to receive(:revoke)
        subject.revoke!
      end

      it "rescues an api error" do
        allow(api_object).to receive(:revoke).and_raise(StandardError)
        expect(subject).to receive(:puts).twice
        expect { subject.revoke! }.to_not raise_error
      end
    end

    context "#group_id" do
      context "given a string" do
        let(:group) { "sec-group" }
        it "returns the passed in string as the security group id" do
          expect(subject.group_id(group)).to equal(group)
        end
      end

      context "given a hash with group_id" do
        let(:group) { { group_id: "sec-group" } }
        it "returns the group id" do
          expect(subject.group_id(group)).to equal(group[:group_id])
        end
      end

      context "given a hash with group_name" do
        let(:group) { { group_name: "sec-group-name" } }
        let(:group_id) { "sec-group" }
        let(:group_hash) { { "sec-group-name" => group_id } }
        it "returns the matching group id" do
          allow(SecurityGroup).to receive(:name_lookup).with(group[:group_name]).and_return(group_id)
          expect(subject.group_id(group)).to equal(group_id)
        end
      end
    end

    context ".rules_from_api" do
      subject { Rule }
      let(:rules) { [double(port_range: 123, protocol: :tcp, ip_ranges: ['0.0.0.0/0'], groups: [double(id: 'sec-group')])] }
      let(:direction) { :outbound }

      it "returns an array of rules" do
        expect(subject.rules_from_api(rules, direction)).to be_an_array_of(Rule)
      end
    end

    context ".rules_from_api" do
      subject { Rule }
      let(:api_rule) { double(port_range: 123, protocol: :tcp, ip_ranges: ['0.0.0.0/0'], groups: [double(id: 'sec-group')]) }
      let(:rules) { [api_rule] }
      let(:direction) { :outbound }

      it "returns an array of rules" do
        expect(subject.rules_from_api(rules, direction)).to be_an_array_of(Rule)
      end
    end

    context ".rules_from_config" do
      subject { Rule }
      let(:config_rule) { { port_range: 123, protocol: :tcp, ip_ranges: ['0.0.0.0/0'], groups: [double(id: 'sec-group')] } }
      let(:direction) { :outbound }
      let(:rules) { {outbound: [config_rule]} }

      it "returns an array of rules" do
        expect(subject.rules_from_config(rules, direction)).to be_an_array_of(Rule)
      end
    end
  end
end
