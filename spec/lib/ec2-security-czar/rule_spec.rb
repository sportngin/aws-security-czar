require 'spec_helper.rb'
require 'ec2-security-czar/rule'

module Ec2SecurityCzar
  describe Rule do
    let(:direction) { :outbound }
    let(:ip_range) { '0.0.0.0/0' }
    let(:group) { 'sec-group' }
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

    context ".rules_from_api" do
      subject { Rule }

    end
  end
end
