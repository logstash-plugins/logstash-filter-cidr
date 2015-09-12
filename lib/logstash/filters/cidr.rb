# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"


# The CIDR filter is for checking IP addresses in events against a list of
# network blocks that might contain it. Multiple addresses can be checked
# against multiple networks, any match succeeds. Upon success additional tags
# and/or fields can be added to the event.

class LogStash::Filters::CIDR < LogStash::Filters::Base

  config_name "cidr"

  # The IP address(es) to check with.
  # Example:
  #
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "testnet" ]
  #         address => [ "%{src_ip}", "%{dst_ip}" ]
  #         network => [ "192.0.2.0/24" ]
  #       }
  #     }
  #
  config :address, :validate => :array, :default => []

  # The IP network(s) to check against.
  #
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         address => [ "%{clientip}" ]
  #         network => [ "169.254.0.0/16", "fe80::/64" ]
  #       }
  #     }
  #
  config :network, :validate => :array, :default => []

  # Are the fields in the address array fields in the event?
  # This will look for a element 'clientip' in the event. This
  # reduces the load if an IP is already stored in an eventfield.
  # 
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         ipeventfield => true
  #         address => [ "clientip" ]
  #         network => [ "%{somenet}/%{netmask}", "169.254.0.0/16", "fe80::/64" ]
  #       }
  #     }
  #
  config :ipeventfield, :validate => :boolean, :default => false
  
  # Are the fields in the network array names of fields in the event?
  # This will look for a field in the event with the given name. This
  # reduces the load if an IP is already stored in an eventfield
  #
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         neteventfield => true
  #         address => [ "%{clientip}" ]
  #         network => [ "ipv4net", "ipv4nettwo", "ipv6net" ]
  #       }
  #     }
  #
  config :neteventfields, :validate => :boolean, :default => false

  # If the ipeventfiled is set to false, strings like 
  # '%{firstbyte}.%{secondbyte}...' in the address array will be not
  # interpreted and used as provided.
  #
  config :ipusesprintf, :validate => :boolean, :default => true

  # If the neteventfiled is set to false, strings like
  # '%{network}/%{netmask}' in the network array not will be interpreted
  # and used as provided
  #
  config :netusesprintf, :validate => :boolean, :default => true
  
       
  public
  def register
    require "ipaddr"
    # use pre allocated array if it is a constant value in the config
    if not ( @netusesprintf or @neteventfields)
      begin 
        @network.collect! do |n|
          IPAddr.new(n)
        end
      rescue
        @logger.warn("Invalid IP network, skipping", :network => n)
      end
      @network.compact!
    end # end of static values

    # use pre allocated array if it is a constant value in the config
    if not ( @ipusesprintf or @ipeventfields)
      begin 
        @address.collect! do |a|
          IPAddr.new(a)
        end
      rescue
        @logger.warn("Invalid IP, skipping", :address => a)
      end
      @address.compact!
    end # end of static values

  end # def register

  public
  def filter(event)
    return unless filter?(event)
    # static values
    if ( @ipusesprintf or @ipeventfields )
      address = @address.collect do |a|
        begin
          if @ipeventfield
            IPAddr.new(event[a])
          else
            IPAddr.new(event.sprintf(a))
          end
        rescue ArgumentError => e
          @logger.warn("Invalid IP address, skipping", :address => a, :event => event)
          nil
        end
      end
      address.compact!
    else
      address = @address
    end

    if ( @netusesprintf or @neteventfields )
      network = @network.collect do |n|
        begin
          if @neteventfields
            IPAddr.new(event[n])
          else
            IPAddr.new(event.sprintf(n))
          end
        rescue ArgumentError => e
          @logger.warn("Invalid IP network, skipping", :network => n, :event => event)
          nil
        end
      end
      network.compact!
    else
      network = @network
    end

    # Try every combination of address and network, first match wins
    address.product(network).each do |a, n|
      @logger.debug("Checking IP inclusion", :address => a, :network => n)
      if n.include?(a)
        filter_matched(event)
        return
      end
    end
  end # def filter
end # class LogStash::Filters::CIDR
