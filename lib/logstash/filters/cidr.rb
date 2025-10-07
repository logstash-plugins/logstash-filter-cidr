# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"
require 'logstash/plugin_mixins/validator_support/field_reference_validation_adapter'

# The CIDR filter is for checking IP addresses in events against a list of
# network blocks that might contain it. Multiple addresses can be checked
# against multiple networks, any match succeeds. Upon success additional tags
# and/or fields can be added to the event.
java_import 'java.util.concurrent.locks.ReentrantReadWriteLock'

class LogStash::Filters::CIDR < LogStash::Filters::Base
  config_name "cidr"

  extend LogStash::PluginMixins::ValidatorSupport::FieldReferenceValidationAdapter

  # The IP address(es) to check with, as a field reference. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "testnet" ]
  #         address_field => "[host][ip]"
  #         network => [ "192.0.2.0/24" ]
  #       }
  #     }
  config :address_field, :validate => :field_reference

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

    if @address_field && !@address.empty? #checks if both address and address_field are defined in configuration options
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "cidr",
        :error => "The configuration options 'address' and 'address_field' are mutually exclusive"
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
  end #def load_file

  public
  def filter(event)
    ips = get_addresses(event).inject([]) do |ips, a|
      begin
        ips << IPAddr.new(a)
      rescue ArgumentError => e
        @logger.warn("Invalid IP address, skipping", :address => a, :event => event.to_hash)
      end
      ips
    end

    if @network_path #in case we are getting networks from an external file
      if needs_refresh?
        lock_for_write do
          if needs_refresh?
            load_file
            @next_refresh = Time.now() + @refresh_interval
          end
        end #end lock
      end #end refresh from file

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

    else #networks come from array in config file

      network = @network.map {|nw| event.sprintf(nw) }.map {|nw| nw.split(",") }.flatten.collect do |n|
        begin
          IPAddr.new(n.strip)
        rescue ArgumentError => e
          @logger.warn("Invalid IP network, skipping", :network => n, :event => event.to_hash)
          nil
        end
      end
    end

    network.compact! #clean nulls
    # Try every combination of address and network, first match wins
    ips.product(network).each do |a, n|
      @logger.debug("Checking IP inclusion", :address => a, :network => n)
      if n.include?(a)
        filter_matched(event)
        return
      end
    end
  end # def filter

  private
  def get_addresses(event)
    if @address_field
      Array(event.get(@address_field))
    else
      @address.collect { |a| event.sprintf(a) }
    end
  end
end # class LogStash::Filters::CIDR
