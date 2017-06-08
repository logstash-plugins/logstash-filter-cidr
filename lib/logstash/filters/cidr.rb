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

  #Where the file containing the IP masks
  config :network_path, :validate => :path

  config :separator,:validate => :string, :default => "\n"

  # When using a file, this setting will indicate how frequently
  # (in seconds) logstash will check the dictionary file for updates.
  config :refresh_interval, :validate => :number, :default => 300


  public
  def register #This portion of code has been borrowed from logstash-filter-translate
    rw_lock = java.util.concurrent.locks.ReentrantReadWriteLock.new
    @read_lock = rw_lock.readLock
    
    if @dictionary_path
      @next_refresh = Time.now + @refresh_interval
      raise_exception = true
      lock_for_write { load_file(raise_exception) }
    end
  end # def register

  def lock_for_read
    @read_lock.lock
    begin
      yield
    ensure
      @read_lock.unlock
    end
  end

  def lock_for_write
    @write_lock.lock
    begin
      yield
    ensure
      @write_lock.unlock
    end
  end

  def needs_refresh()
    @next_refresh < Time.now
  end

  public 
  def load_file()
    @network = File.open(@network_path,"r") {|file| file.read.split(@separator)}

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

    if @network_path #case we are getting networks from a file
      if needs_refresh?
        load_file
      end
      network = @network.collect do |n|
      begin
          IPAddr.new(n)
      rescue ArgumentError => e
        @logger.warn("")
      end
    else
      network = @network.collect do |n|
        begin
          IPAddr.new(event.sprintf(n))
        rescue ArgumentError => e
          @logger.warn("Invalid IP network, skipping", :network => n, :event => event)
          nil
        end
      end
    network.compact!

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
