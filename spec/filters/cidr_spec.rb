require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/cidr"

describe LogStash::Filters::CIDR do

  let(:config) { Hash.new }
  subject { described_class.new(config) }
  # IPV4
  describe "IPV4 match test" do
    config <<-CONFIG
      filter {
        cidr {
          address => [ "%{clientip}" ]
          network => [ "192.168.0.0/24" ]
          add_tag => [ "matched" ]
        }
      }
    CONFIG

    sample({"clientip" => "192.168.0.30"}) do
      insist { subject.get("tags") }.include?("matched")
    end
  end

  describe "IPV4 non match" do
   config <<-CONFIG
       filter {
        cidr {
          address => [ "%{clientip}" ]
          network => [ "192.168.0.0/24" ]
          add_tag => [ "matched" ]
        }
      }
    CONFIG

    sample({"clientip" => "123.52.122.33"}) do
      insist { subject.get("tags") }.nil?
    end
  end

  # Test multple CIDR blocks passed into 'network'.  Make sure we try an
  # IP in every range.

  describe "IPV4 match, passing a list to network [192.168.0.30]" do
   config <<-CONFIG
       filter {
        cidr {
          address => [ "%{clientip}"]
          network => [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
          add_tag => [ "matched" ]
        }
      }
    CONFIG

    sample({"clientip" => "192.168.0.30"}) do
      insist { subject.get("tags") }.include?("matched")
    end

    sample({"clientip" => "10.10.220.3"}) do
      insist { subject.get("tags") }.include?("matched")
    end

    sample({"clientip" => "172.16.45.50"}) do
      insist { subject.get("tags") }.include?("matched")
    end

    # No match
    sample({"clientip" => "8.8.8.8"}) do
      insist { subject.get("tags") }.nil?
    end

  end
  describe "IPV4 match, passing a string with a list to network" do
   config <<-CONFIG
       filter {
        cidr {
          address => [ "%{clientip}"]
          network => [ "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"]
          add_tag => [ "matched" ]
        }
      }
    CONFIG

    sample({"clientip" => "192.168.0.30"}) do
      insist { subject.get("tags") }.include?("matched")
    end

    context "when network list comes in a field reference" do
      config <<-CONFIG
          filter {
           cidr {
             address => [ "%{clientip}"]
             network => [ "%{whitelist}"]
             add_tag => [ "matched" ]
           }
         }
      CONFIG
      sample({"whitelist" => [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "clientip" => "192.168.0.30"}) do
        insist { subject.get("tags") }.include?("matched")
      end
    end
  end


  # IPV6

  describe "IPV6 match test" do
    config <<-CONFIG
      filter {
        cidr {
          address => [ "%{clientip}" ]
          network => [ "fe80::/64" ]
          add_tag => [ "matched" ]
        }
      }
    CONFIG

    sample({"clientip" => "fe80:0:0:0:0:0:0:1"}) do
      insist { subject.get("tags") }.include?("matched")
    end
  end

  describe "IPV6 non match" do
   config <<-CONFIG
       filter {
        cidr {
          address => [ "%{clientip}" ]
          network => [ "fe80::/64" ]
          add_tag => [ "matched" ]
        }
      }
    CONFIG

    sample({"clientip" => "fd82:0:0:0:0:0:0:1"}) do
      insist { subject.get("tags") }.nil?
    end
  end

  describe "Load network list from a file" do

    let(:network_path) {File.join(File.dirname(__FILE__), "..", "files", "network")}
    let(:config) do
      "filter { cidr { network_path => \"#{network_path}\" address => \"%{clientip}\" add_tag => \[\"matched\"] }}"
    end

    sample({"clientip" => "192.168.1.1"}) do
      insist { subject.get("tags") }.include?("matched")
    end

    sample({"clientip" => "200.17.160.201"}) do
      insist { subject.get("tags") }.include?("matched")
    end

    sample({"clientip" => "10.1.2.1"}) do
      insist { subject.get("tags").nil? }
    end
  end

  describe "Try different separator character" do

    let(:network_path) {File.join(File.dirname(__FILE__), "..", "files", "network-comma")}
    let(:config) do
      "filter { cidr { network_path => \"#{network_path}\" address => \"%{clientip}\" add_tag => \[\"matched\"] separator => \",\" }}"
    end

    sample({"clientip" => "192.168.1.25"}) do
      insist { subject.get("tags").include?("matched")}
    end

    sample({"clientip" => "192.167.1.1"}) do
      insist { subject.get("tags").nil? }
    end

  end

  describe "general configuration" do
    let(:network_path) {File.join(File.dirname(__FILE__), "..", "files", "network")}
    let(:config) do
      {
        "address"        => [ "%{clientip}" ],
        "network"        => ["192.168.1.0/24"],
        "network_path"   => network_path,
        "add_tag"        => ["matched"]
      }
    end

    it "raises an exception if both 'network' and 'network_path' are set" do
      expect { subject.register }.to raise_error(
        LogStash::ConfigurationError,
        /The configuration options 'network' and 'network_path' are mutually exclusive/
      )
    end
  end

  describe "address_field config option" do

    context 'the field is top-level' do

      config <<-CONFIG
        filter {
          cidr {
            address_field => "ip"
            network => [ "192.168.0.0/24" ]
            add_tag => [ "matched" ]
          }
        }
      CONFIG

      context 'the input value is a string' do
        sample({ "ip" => "192.168.0.1" }) do
          insist { subject.get("tags") }.include?("matched")
        end
      end

      context 'the input value is an array' do
        sample({ "ip" => [ "188.168.0.1", "192.168.0.1" ] }) do
          insist { subject.get("tags") }.include?("matched")
        end
      end

      context 'the input value contains an invalid ip' do
        sample({ "ip" => [ "invalid", "192.168.0.1" ] }) do
          insist { subject.get("tags") }.include?("matched")
        end
      end
    end

    context 'the field is nested' do

      config <<-CONFIG
        filter {
          cidr {
            address_field => "[host][ip]"
            network => [ "192.168.0.0/24" ]
            add_tag => [ "matched" ]
          }
        }
      CONFIG

      sample({ "host" => { "ip" => [ "188.168.0.1", "192.168.0.1" ] } }) do
        insist { subject.get("tags") }.include?("matched")
      end
    end

    context 'address and address_field are both defined' do

      let(:config) do
        {
          "address_field" => "[host][ip]",
          "address" => [ "%{clientip}" ]
        }
      end

      it "raises an exception" do
        expect { subject.register }.to raise_error(
          LogStash::ConfigurationError,
          /The configuration options 'address' and 'address_field' are mutually exclusive/
        )
      end
    end
  end
end
