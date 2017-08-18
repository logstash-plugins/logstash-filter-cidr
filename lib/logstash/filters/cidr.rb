# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "logstash-filter-cidr_jars"

# The CIDR filter is for checking IP addresses in events against a list of
# network blocks that might contain it. Multiple addresses can be checked
# against multiple networks, any match succeeds. Upon success additional tags
# and/or fields can be added to the event.


class LogStash::Filters::CIDR < LogStash::Filters::Base
  java_import com.github.veqryn.net.Ip4
  java_import com.github.veqryn.net.Cidr4
  java_import com.github.veqryn.collect.Cidr4Trie
  java_import java.util.concurrent.locks.ReentrantReadWriteLock

  config_name "cidr"

  # The IPv4 address(es) to check with. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "testnet" ]
  #         address => [ "%{src_ip}", "%{dst_ip}" ]
  #         network => [ "192.0.2.0/24" ]
  #       }
  #     }
  config :address, :validate => :array, :default => []

  # The IPv4 network(s) to check against. Example:
  # [source,ruby]
  #     filter {
  #       %PLUGIN% {
  #         add_tag => [ "linklocal" ]
  #         address => [ "%{clientip}" ]
  #         network => [ "169.254.0.0/16", "10.0.0.0/8" ]
  #       }
  #     }
  config :network, :validate => :array, :default => []

  # The full path of the external file containing the IPv4 network(s) to check against. Example:
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
    rw_lock = ReentrantReadWriteLock.new
    @read_lock = rw_lock.readLock
    @write_lock = rw_lock.writeLock
    @network_trie = Cidr4Trie.new

    if @network_path && !@network.empty? #checks if both network and network path are defined in configuration options
      raise LogStash::ConfigurationError, I18n.t(
        "logstash.agent.configuration.invalid_plugin_register",
        :plugin => "filter",
        :type => "cidr",
        :error => "The configuration options 'network' and 'network_path' are mutually exclusive"
      )
    end

    lock_for_write do
      if @network_path
        load_file
      else
        load_inline
      end
    end # end lock
  end # def register

  def check_for_refresh
    if @network_path and needs_refresh?
      lock_for_write do
        if needs_refresh?
          load_file
        end
      end # end lock
    end
  end # def check_for_refresh

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

  def load_inline
    load_trie(@network)
  end # def load_inline

  def load_file
    @next_refresh = Time.now() + @refresh_interval
    begin
      temporary = File.open(@network_path, "r") {|file| file.read.split(@separator)}
      if !temporary.empty? #ensuring the file was parsed correctly
        load_trie(temporary)
      end
    rescue
      if !@network_trie.empty? #if the list was parsed successfully before
        @logger.error("Error while refreshing network list file")
      else
        raise LogStash::ConfigurationError, I18n.t(
          "logstash.agent.configuration.invalid_plugin_register",
          :plugin => "filter",
          :type => "cidr",
          :error => "Network list file is invalid, please check the separator character or permissions for the file."
        )
      end
    end
  end #def load_file

  def load_trie(networks)
    @network_trie.clear
    networks.each do |n|
      begin
        @network_trie.put(Cidr4.new(n), n)
      rescue Java::JavaLang::IllegalArgumentException
        @logger.warn("Invalid IP network, skipping", :network => n)
      end
    end
  end # def load_trie

  public
  def filter(event)
    check_for_refresh
    @address.each do |a|
      begin
        ip = Ip4.new(event.sprintf(a))
        prefix = nil
        lock_for_read do
          prefix = @network_trie.shortestPrefixOfValue(ip.getCidr, true)
        end # end lock
        if prefix
          filter_matched(event)
          return
        end
      rescue Java::JavaLang::IllegalArgumentException => e
        @logger.warn("Invalid IP address, skipping", :address => a, :event => event)
      end
    end
  end # def filter
end # class LogStash::Filters::CIDR
