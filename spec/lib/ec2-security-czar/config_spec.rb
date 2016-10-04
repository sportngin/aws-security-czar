require 'spec_helper'
require 'aws_security_czar'

module AwsSecurityCzar
  describe GlobalConfig do

    context "config key methods" do
      it "should return nil when not set" do
        expect(GlobalConfig.doesnt_exist).to eql(nil)
        expect(GlobalConfig.doesnt_exist?).to eql(false)
      end
      it "should return the config value when set" do
        GlobalConfig.new_value = "testing"
        expect(GlobalConfig.new_value).to eql("testing")
      end
    end

    context "after loading a config file" do
      before do
        config_file = {"domain"=>"example_domain", "slack"=>{"slack_option"=>true, "username"=>"Rspec Tester", "icon_url"=>"http://fake.url", "channel"=>"#test-channel", "webhook"=>"https://slack.web.hook"}}
        allow(YAML).to receive(:load_file).and_return(config_file)
        allow(File).to receive(:exist?).and_return(true)
        GlobalConfig.load("dummy/path")
      end

      it "calling a method corresponding to a key in the file should return the value" do
        expect(GlobalConfig.domain).to eql("example_domain")
        expect(GlobalConfig.slack).to be_kind_of(Hash)
        expect(GlobalConfig.slack[:slack_option]).to eql(true)
      end

      it "overwriting values should work" do
        expect(GlobalConfig.slack).to be_kind_of(Hash)
        GlobalConfig.slack = "this is a string now"
        expect(GlobalConfig.slack).to eql("this is a string now")
      end

    end
  end
end

