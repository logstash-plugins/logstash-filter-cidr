# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"

# The CIDR filter is for checking IP addresses in events against a list of
# network blocks that might contain it. Multiple addresses can be checked
# against multiple networks, any match succeeds. Upon success additional tags
# and/or fields can be added to the event.
java_import 'java.util.concurrent.locks.ReentrantReadWriteLock'

class LogStash::Filters::CIDR < LogStash::Filters::Base

  config_name "cidr"

  # The IP address(es) to check with. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "testnet" ]
  #         address => [ "%{src_ip}", "%{dst_ip}" ]
  #         network => [ "192.0.2.0/24" ]
  #       }
  #     }
  config :address, :validate => :array, :default => []

  # The IP network(s) to check against. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         address => [ "%{clientip}" ]
  #         network => [ "169.254.0.0/16", "fe80::/64" ]
  #       }
  #     }
  config :network, :validate => :array, :default => []

  # The full path of the external file containing the IP network(s) to check against. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         address => [ "%{clientip}" ]
  #         network_path => "/etc/logstash/networks"
  #       }
  #     }
  # NOTE: it is an error to specify both 'network' and 'network_path'.
  config :network_path, :validate => :path

  # The separator character used in the encoding of the external file pointed by network_path.
  config :separator,:validate => :string, :default => "\n"

  # When using a network list from a file, this setting will indicate how frequently
  # (in seconds) logstash will check the file for updates.
  config :refresh_interval, :validate => :number, :default => 300

  public
  def register    
    rw_lock = java.util.concurrent.locks.ReentrantReadWriteLock.new
    @read_lock = rw_lock.readLock

    if @network_path && !@network.empty?
    	raise LogStash::ConfigurationError, I18n.t(
    	"logstash.agent.configuration.invalid_plugin_register",
    	:plugin => "filter",
    	:type => "cidr",
    	:error => "The configuration options 'network' and 'network_path' are mutually exclusive"
    	)
    end
 
    if @network_path
      @next_refresh = Time.now + @refresh_interval
      lock_for_read { load_file }
    end
  end # def register

  def lock_for_read #ensuring only one thread updates the network block list
    @read_lock.lock
    begin
      yield
    ensure
      @read_lock.unlock
    end
  end #define lock_for_read

  def needs_refresh?
    @next_refresh < Time.now
  end # define needs_refresh

  def load_file
    if @network && !File.exists?(@network_path)
      @logger.warn("file read error, continuing with old version")
    end

    begin
      temporary = File.open(@network_path,"r") {|file| file.read.split(@separator)}
      if !temporary.empty? #ensuring the file was parsed correctly
        @network = temporary
      end
    rescue
      if @network
        @logger.error("Error while opening/parsing the file")
      else
        raise LogStash::ConfigurationError, I18n.t(
          "logstash.agent.configuration.invalid_plugin_register",
          :plugin => "filter",
          :type => "cidr",
          :error => "The file containing the network list is invalid, please check the separator character or permissions for the file."
        )
      end
    end
  end #def load_file
  
  public
  def filter(event)
    address = @address.collect do |a|
      begin
        IPAddr.new(event.sprintf(a))
      rescue ArgumentError => e
        @logger.warn("Invalid IP address, skipping", :address => a, :event => event)
        nil
      end
    end
    address.compact!

    if @network_path #in case we are getting networks from a file
      if needs_refresh?
        lock_for_read do
          if needs_refresh?
      	    load_file
      	    @next_refresh = Time.now() + @refresh_interval
	  end
        end
      end

      network = @network.collect do |n|
        begin
          IPAddr.new(n)
  	    rescue ArgumentError => e
              @logger.warn("Invalid IP network, skipping", :network => n, :event => event)
  	    end
        end

    else #case networks come from array in config file

      network = @network.collect do |n|
        begin
          IPAddr.new(event.sprintf(n))
        rescue ArgumentError => e
          @logger.warn("Invalid IP network, skipping", :network => n, :event => event)
          nil
        end
      end
    end

    network.compact! #clean nulls

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
