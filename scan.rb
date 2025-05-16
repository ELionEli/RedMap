#!/usr/bin/env ruby

require 'socket'
require 'optparse'
require 'timeout'
require 'ipaddr'
require 'thread'

class NetworkScanner
  def initialize(network_range, timeout = 0.5)
    @network_range = network_range
    @timeout = timeout
    @live_hosts = []
    @mutex = Mutex.new
    @thread_count = 32  # Number of concurrent threads
  end

  def scan_network
    puts "\nStarting network scan for range: #{@network_range}"
    puts "=" * 50

    network = IPAddr.new(@network_range)
    ips = network.to_range.to_a
    total_ips = ips.count
    completed = 0

    # Split IPs into chunks for threading
    ip_chunks = ips.each_slice((ips.size.to_f / @thread_count).ceil).to_a
    threads = []

    # Create progress tracking variables
    @mutex.synchronize { @completed_ips = 0 }
    @total_ips = total_ips

    # Start scanning threads
    ip_chunks.each do |ip_chunk|
      threads << Thread.new do
        ip_chunk.each do |ip|
          if quick_host_check(ip.to_s)
            host_info = {
              ip: ip.to_s,
              hostname: get_hostname(ip.to_s),
              mac: get_mac_address(ip.to_s)
            }
            @mutex.synchronize do
              @live_hosts << host_info
              puts "\nFound live host: #{ip}"
            end
          end
          
          # Update progress
          @mutex.synchronize do
            @completed_ips += 1
            display_progress
          end
        end
      end
    end

    threads.each(&:join)
    puts "\n"  # New line after progress bar
    display_network_results
  end

  private

  def display_progress
    width = 50
    progress = (@completed_ips.to_f / @total_ips * width).to_i
    percentage = (@completed_ips.to_f / @total_ips * 100).to_i
    print "\rProgress: [#{"=" * progress}#{" " * (width - progress)}] #{percentage}%"
  end

  def quick_host_check(ip)
    # Try most common port first
    begin
      Timeout.timeout(@timeout) do
        TCPSocket.new(ip, 80).close
        return true
      end
    rescue
      # If port 80 fails, try a quick ping
      return system("ping -n 1 -w 500 #{ip} > nul 2>&1")
    end
    false
  end

  def get_hostname(ip)
    begin
      Timeout.timeout(1) do  # Add timeout for DNS resolution
        Addrinfo.ip(ip).getnameinfo[0]
      end
    rescue
      'Unknown'
    end
  end

  def get_mac_address(ip)
    return 'N/A' unless RUBY_PLATFORM =~ /win32/
    
    begin
      Timeout.timeout(1) do  # Add timeout for ARP
        arp_output = `arp -a #{ip}`
        if arp_output =~ /([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})/
          return $1
        end
      end
    rescue
      'N/A'
    end
    'N/A'
  end

  def display_network_results
    puts "\nNetwork scan completed!"
    puts "=" * 50
    puts "Results for network #{@network_range}:"
    puts "#{@live_hosts.length} live hosts found"
    
    if @live_hosts.any?
      puts "\nLive hosts:"
      puts sprintf("%-15s %-30s %-20s", "IP Address", "Hostname", "MAC Address")
      puts "-" * 65
      @live_hosts.each do |host|
        puts sprintf("%-15s %-30s %-20s", 
          host[:ip],
          host[:hostname],
          host[:mac]
        )
      end
    end
  end
end

class PortScanner
  def initialize(target, start_port, end_port, timeout = 2)
    @target = target
    @start_port = start_port
    @end_port = end_port
    @timeout = timeout
    @common_services = {
      21 => 'FTP',
      22 => 'SSH',
      23 => 'Telnet',
      25 => 'SMTP',
      53 => 'DNS',
      80 => 'HTTP',
      110 => 'POP3',
      143 => 'IMAP',
      443 => 'HTTPS',
      445 => 'SMB',
      3306 => 'MySQL',
      5432 => 'PostgreSQL',
      27017 => 'MongoDB'
    }
  end

  def scan
    puts "\nStarting port scan for #{@target}"
    puts "Scanning ports #{@start_port} to #{@end_port}"
    puts "=" * 50

    open_ports = []
    
    (@start_port..@end_port).each do |port|
      print "\rScanning port #{port}..."
      
      begin
        Timeout.timeout(@timeout) do
          socket = TCPSocket.new(@target, port)
          service = @common_services[port] || 'unknown'
          puts "\nPort #{port} is open (#{service})"
          socket.close
          open_ports << port
        end
      rescue Errno::ECONNREFUSED
        # Port is closed
      rescue Timeout::Error
        puts "\nPort #{port} filtered (timeout)"
      rescue Errno::EHOSTUNREACH
        puts "\nHost seems to be down or unreachable"
        break
      rescue => e
        puts "\nError scanning port #{port}: #{e.message}"
      end
    end

    display_results(open_ports)
  end

  private

  def display_results(open_ports)
    puts "\n\nScan completed!"
    puts "=" * 50
    puts "Results for #{@target}:"
    puts "#{open_ports.length} open ports found"
    
    if open_ports.any?
      puts "\nOpen ports:"
      open_ports.each do |port|
        service = @common_services[port] || 'unknown'
        puts "#{port}/tcp\t#{service}"
      end
    end
  end
end

# Parse command line arguments
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: ruby_scanner.rb [options]"

  opts.on("-t", "--target TARGET", "Target host to scan") do |t|
    options[:target] = t
  end

  opts.on("-s", "--start-port PORT", Integer, "Start port (default: 1)") do |s|
    options[:start_port] = s
  end

  opts.on("-e", "--end-port PORT", Integer, "End port (default: 1024)") do |e|
    options[:end_port] = e
  end

  opts.on("-n", "--network RANGE", "Network range to scan (e.g., 192.168.1.0/24)") do |n|
    options[:network] = n
  end

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit
  end
end.parse!

if options[:network]
  # Network scanning mode
  scanner = NetworkScanner.new(options[:network])
  scanner.scan_network
else
  # Port scanning mode
  options[:target] ||= 'localhost'
  options[:start_port] ||= 1
  options[:end_port] ||= 1024

  scanner = PortScanner.new(
    options[:target],
    options[:start_port],
    options[:end_port]
  )
  scanner.scan
end
