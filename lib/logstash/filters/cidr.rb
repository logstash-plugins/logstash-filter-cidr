# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"
require "json"

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
  config :network, :validate => :array || :hash , :default => []
  
  # The type of data in the external file containing the IP network(s) to check against. Can be "Array" or "Hash". 
  # If set to "Hash", file must be json formatted. Does nothing unless network_path is set. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         address => [ "%{clientip}" ]
  #         network_type => "Hash"
  #         network_path => "/etc/logstash/networks.json"
  #       }
  #     }
  config :network_type, :validate => :string, :default => "Array"

  # Return the data corresponding to the network(s) Hash(es). 
  # If set to true, corresponding hash will be returned to a specified field, or "result" if none are specified. Does nothing unless network_type is Hash. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         address => [ "%{clientip}" ]
  #         network_type => "Hash"
  #         network_path => "/etc/logstash/networks.json"
  #         network_return => true
  #       }
  #     }
  config :network_return, :validate => :boolean, :default => false

  # The field with which to return the data corresponding to the network(s) Hash(es). 
  # If set, corresponding hash will be returned to a specified field, "result" if not specified. Does nothing unless network_type is Hash. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         address => [ "%{clientip}" ]
  #         network_type => "Hash"
  #         network_path => "/etc/logstash/networks.json"
  #         network_return => true
  #         target => "FieldName"
  #       }
  #     }
  config :target, :validate => :string, :default => "result"

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

  # When using a network list from a file, this setting will indicate
  # how frequently (in seconds) Logstash will check the file for
  # updates.
  config :refresh_interval, :validate => :number, :default => 600

  # The separator character used in the encoding of the external file
  # pointed by network_path.
  config :separator, :validate => :string, :default => "\n"

  public
  def register
    rw_lock = java.util.concurrent.locks.ReentrantReadWriteLock.new
    @read_lock = rw_lock.readLock
    @write_lock = rw_lock.writeLock

    if @network_path && !@network.empty? #checks if both network and network path are defined in configuration options
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "cidr",
        :error => "The configuration options 'network' and 'network_path' are mutually exclusive"
      )
    end

    if @network_path
      @next_refresh = Time.now + @refresh_interval
      lock_for_write { load_file }
    end
  end # def register

  def lock_for_write
    @write_lock.lock
    begin
      yield
    ensure
      @write_lock.unlock
    end
  end # def lock_for_write

  def lock_for_read #ensuring only one thread updates the network block list
    @read_lock.lock
    begin
      yield
    ensure
      @read_lock.unlock
    end
  end #def lock_for_read

  def needs_refresh?
    @next_refresh < Time.now
  end # def needs_refresh

  def load_file
    if @network_type.eql?("Hash")
      begin
        json_temporary = File.read(@network_path)
	temporary = JSON.parse(json_temporary)
        if !temporary.empty? #ensuring the file was parsed correctly
          @network_list = temporary
        end
      rescue
        if @network_list #if the list was parsed successfully before
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
    elsif @network_type.eql?("Array")
      begin
        temporary = File.open(@network_path, "r") {|file| file.read.split(@separator)}
        if !temporary.empty? #ensuring the file was parsed correctly
          @network_list = temporary
        end
      rescue
        if @network_list #if the list was parsed successfully before
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
    else
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "cidr",
        :error => "When defining network_type, value must be one of Array or Hash."
      )
    end
  end #def load_file

  public
  def filter(event)
    address = @address.collect do |a|
      begin
        IPAddr.new(event.sprintf(a))
      rescue ArgumentError => e
        @logger.warn("Invalid IP address, skipping", :address => a, :event => event.to_hash)
        nil
      end
    end
    address.compact!

    if @network_path #in case we are getting networks from an external file
      if needs_refresh?
        lock_for_write do
          if needs_refresh?
            load_file
            @next_refresh = Time.now() + @refresh_interval
          end
        end #end lock
      end #end refresh from file
      if @network_type.eql?("Hash")
	network = @network_list.keys.collect do |n|
          begin
            lock_for_read do
              IPAddr.new(n)
            end
          rescue ArgumentError => e
            @logger.warn("Invalid IP network, skipping", :network => n, :event => event.to_hash)
            nil
          end
        end
      
      elsif @network_type.eql?("Array")
        network = @network_list.collect do |n|
          begin
            lock_for_read do
              IPAddr.new(n)
            end
          rescue ArgumentError => e
            @logger.warn("Invalid IP network, skipping", :network => n, :event => event.to_hash)
            nil
          end
        end
      end
    else #networks come from array in config file
      if @network.is_a?(Hash)
        network = @network.keys {|nw| event.sprintf(nw) }.map {|nw| nw.split(",") }.flatten.collect do |n|
          begin
            IPAddr.new(n.strip)
          rescue ArgumentError => e
            @logger.warn("Invalid IP network, skipping", :network => n, :event => event.to_hash)
            nil
          end
        end
      elsif @network.is_a?(Array)
        network = @network.map {|nw| event.sprintf(nw) }.map {|nw| nw.split(",") }.flatten.collect do |n|
          begin
            IPAddr.new(n.strip)
          rescue ArgumentError => e
            @logger.warn("Invalid IP network, skipping", :network => n, :event => event.to_hash)
            nil
          end
        end
      end
      network = network.sort_by{ |net| -net.prefix() }
    end

    network.compact! #clean nulls
    # Try every combination of address and network, first match wins
    address.product(network).each do |a, n|
      @logger.debug("Checking IP inclusion", :address => a, :network => n)
      if n.include?(a)
	if (@network.is_a?(Hash) || @network_list.is_a?(Hash)) and @network_return
	  if @network.is_a?(Hash)
	    val = @network["#{n.to_s}/#{n.prefix()}"]
	  elsif @network_list.is_a?(Hash)
	    val = @network_list["#{n.to_s}/#{n.prefix()}"]
	  end
	  event.set(@target, val)
          filter_matched(event)
          return
	else
          filter_matched(event)
          return
	end
      end
    end
  end # def filter
end # class LogStash::Filters::CIDR
