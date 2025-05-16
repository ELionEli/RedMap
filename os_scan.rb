#!/usr/bin/env ruby

require 'socket'
require 'timeout'
require 'optparse'
require 'ipaddr'
require 'thread'

class OSScanner
  def initialize(target_ip, timeout = 1)
    @target_ip = target_ip
    @timeout = timeout
    @common_ports = {
      21 => 'FTP',
      22 => 'SSH',
      23 => 'Telnet',
      80 => 'HTTP',
      443 => 'HTTPS',
      445 => 'SMB',
      3389 => 'RDP',  # Windows Remote Desktop
      5555 => 'ADB',  # Android Debug Bridge
      8080 => 'HTTP-Alt', # Common Android dev port
      62078 => 'Android-Sync' # Android sync service
    }
  end

  def scan
    os_info = {
      ttl_guess: analyze_ttl,
      service_banners: grab_service_banners,
      smb_info: check_smb,
      rdp_info: check_rdp,
      netbios_info: check_netbios,
      android_info: check_android_services
    }

    determine_os(os_info)
  end

  private

  def analyze_ttl
    # Use ping to get TTL value
    ping_output = `ping -n 1 #{@target_ip}`
    if ping_output =~ /TTL=(\d+)/i
      ttl = $1.to_i
      # Note: TTL alone is not reliable as it can be modified
      # We'll use it as just one factor among many
      {
        ttl: ttl,
        likely_os: 'Unknown'  # We'll determine OS using multiple factors
      }
    else
      { ttl: 'Unknown', likely_os: 'Unknown' }
    end
  end

  def grab_service_banners
    banners = {}
    
    @common_ports.each do |port, service|
      begin
        Timeout.timeout(@timeout) do
          socket = TCPSocket.new(@target_ip, port)
          
          case port
          when 80, 443
            socket.print "HEAD / HTTP/1.0\r\n\r\n"
          when 22
            # Just read SSH banner
          end

          banner = socket.recv(1024).strip
          banners[service] = banner unless banner.empty?
          socket.close
        end
      rescue
        next
      end
    end
    banners
  end

  def check_smb
    begin
      # Try to detect Windows shares
      Timeout.timeout(@timeout) do
        socket = TCPSocket.new(@target_ip, 445)
        return { has_smb: true, details: 'SMB port open (likely Windows)' }
      end
    rescue
      return { has_smb: false, details: 'No SMB detected' }
    end
  end

  def check_rdp
    begin
      Timeout.timeout(@timeout) do
        socket = TCPSocket.new(@target_ip, 3389)
        return { has_rdp: true, details: 'RDP port open (likely Windows)' }
      end
    rescue
      return { has_rdp: false, details: 'No RDP detected' }
    end
  end

  def check_netbios
    begin
      # Check NetBIOS name service (port 137)
      Timeout.timeout(@timeout) do
        socket = TCPSocket.new(@target_ip, 137)
        return { has_netbios: true, details: 'NetBIOS detected (likely Windows)' }
      end
    rescue
      return { has_netbios: false, details: 'No NetBIOS detected' }
    end
  end

  def check_android_services
    android_indicators = {
      has_adb: false,
      has_sync: false,
      has_mdns: false,
      android_ports: []
    }

    # Check for ADB (Android Debug Bridge)
    begin
      Timeout.timeout(@timeout) do
        socket = TCPSocket.new(@target_ip, 5555)
        android_indicators[:has_adb] = true
        android_indicators[:android_ports] << 5555
        socket.close
      end
    rescue
      # ADB not found
    end

    # Check for Android sync service
    begin
      Timeout.timeout(@timeout) do
        socket = TCPSocket.new(@target_ip, 62078)
        android_indicators[:has_sync] = true
        android_indicators[:android_ports] << 62078
        socket.close
      end
    rescue
      # Sync service not found
    end

    # Check for mDNS (common on Android)
    begin
      Timeout.timeout(@timeout) do
        socket = UDPSocket.new
        socket.send("", 0, @target_ip, 5353)
        android_indicators[:has_mdns] = true
        socket.close
      end
    rescue
      # mDNS not found
    end

    # Try HTTP request to common Android ports
    [8080, 8081, 8082].each do |port|
      begin
        Timeout.timeout(@timeout) do
          socket = TCPSocket.new(@target_ip, port)
          socket.print "HEAD / HTTP/1.0\r\nUser-Agent: Android\r\n\r\n"
          response = socket.recv(1024).downcase
          if response.include?('android') || response.include?('dalvik')
            android_indicators[:android_ports] << port
          end
          socket.close
        end
      rescue
        next
      end
    end

    android_indicators
  end

  def determine_os(os_info)
    score = {
      'Windows' => 0,
      'Linux/Unix' => 0,
      'Network Device' => 0,
      'macOS' => 0,
      'Android' => 0  # Added Android score
    }

    # Check for Windows-specific services
    score['Windows'] += 3 if os_info[:smb_info][:has_smb]
    score['Windows'] += 3 if os_info[:rdp_info][:has_rdp]
    score['Windows'] += 2 if os_info[:netbios_info][:has_netbios]

    # Check for Android-specific indicators
    android_info = os_info[:android_info]
    score['Android'] += 3 if android_info[:has_adb]
    score['Android'] += 2 if android_info[:has_sync]
    score['Android'] += 1 if android_info[:has_mdns]
    score['Android'] += android_info[:android_ports].length

    # Analyze TTL but with less weight
    ttl = os_info[:ttl_guess][:ttl]
    if ttl.is_a?(Integer)
      if ttl <= 128 && ttl > 64
        score['Windows'] += 1
      elsif ttl == 64
        score['Android'] += 1  # Android often uses TTL 64
      end
    end

    # Analyze service banners with improved pattern matching
    os_info[:service_banners].each do |service, banner|
      banner = banner.downcase
      
      # Windows signatures
      if banner =~ /microsoft|windows|win32|win64|iis|aspnet|\.net/
        score['Windows'] += 2
      end
      
      # Linux signatures
      if banner =~ /ubuntu|debian|centos|fedora|redhat|apache|nginx|linux/
        score['Linux/Unix'] += 2
      end
      
      # macOS signatures
      if banner =~ /darwin|mac|osx|apple/
        score['macOS'] += 2
      end

      # Network device signatures
      if banner =~ /cisco|juniper|huawei|mikrotik|ubiquiti|router|switch/
        score['Network Device'] += 2
      end

      # Android signatures
      if banner =~ /android|dalvik|okhttp|chrome.*mobile|android.*chrome/
        score['Android'] += 2
      end
    end

    # Additional Windows indicators
    if os_info[:service_banners]['SMB'] || os_info[:service_banners]['RDP']
      score['Windows'] += 2
    end

    # Get the OS with highest score
    likely_os = score.max_by { |k, v| v }

    # Require a minimum confidence score
    detected_os = if likely_os[1] >= 2
      likely_os[0]
    else
      'Unknown'
    end

    {
      detected_os: detected_os,
      confidence_score: likely_os[1],
      raw_data: {
        ttl_info: os_info[:ttl_guess],
        smb_info: os_info[:smb_info],
        rdp_info: os_info[:rdp_info],
        netbios_info: os_info[:netbios_info],
        android_info: os_info[:android_info],
        service_banners: os_info[:service_banners]
      }
    }
  end
end

class NetworkOSScanner
  def initialize(network_range, timeout = 1)
    @network_range = network_range
    @timeout = timeout
    @mutex = Mutex.new
    @thread_count = 16
    @results = []
  end

  def scan_network
    puts "\nStarting OS detection scan for network: #{@network_range}"
    puts "=" * 60
    puts "This might take a while as we gather OS information..."
    puts "=" * 60

    network = IPAddr.new(@network_range)
    ips = network.to_range.to_a
    @total_ips = ips.count
    @completed_ips = 0

    # Split IPs into chunks for threading
    ip_chunks = ips.each_slice((@total_ips.to_f / @thread_count).ceil).to_a
    threads = []

    ip_chunks.each do |ip_chunk|
      threads << Thread.new do
        ip_chunk.each do |ip|
          if host_alive?(ip.to_s)
            scan_result = scan_host(ip.to_s)
            @mutex.synchronize do
              @results << scan_result
              display_host_result(scan_result)
            end
          end
          @mutex.synchronize do
            @completed_ips += 1
            display_progress
          end
        end
      end
    end

    threads.each(&:join)
    display_final_results
  end

  private

  def host_alive?(ip)
    begin
      Timeout.timeout(@timeout) do
        TCPSocket.new(ip, 80).close
        return true
      end
    rescue
      system("ping -n 1 -w 500 #{ip} > nul 2>&1")
    end
  end

  def scan_host(ip)
    puts "\nScanning OS for host: #{ip}"
    scanner = OSScanner.new(ip)
    result = scanner.scan
    {
      ip: ip,
      os_info: result
    }
  end

  def display_progress
    width = 50
    progress = (@completed_ips.to_f / @total_ips * width).to_i
    percentage = (@completed_ips.to_f / @total_ips * 100).to_i
    print "\rProgress: [#{"=" * progress}#{" " * (width - progress)}] #{percentage}%"
  end

  def display_host_result(result)
    puts "\nHost: #{result[:ip]}"
    puts "Detected OS: #{result[:os_info][:detected_os]}"
    puts "Confidence Score: #{result[:os_info][:confidence_score]}"
    puts "-" * 40
  end

  def display_final_results
    puts "\n\nScan Complete!"
    puts "=" * 60
    puts "Found #{@results.length} live hosts"
    puts "\nDetailed Results:"
    puts "=" * 60

    @results.each do |result|
      puts "\nIP: #{result[:ip]}"
      puts "Operating System: #{result[:os_info][:detected_os]}"
      puts "Confidence Score: #{result[:os_info][:confidence_score]}"
      puts "TTL Info: #{result[:os_info][:raw_data][:ttl_info][:ttl]}"
      
      # Display Android-specific information if available
      if result[:os_info][:detected_os] == 'Android'
        android_info = result[:os_info][:raw_data][:android_info]
        puts "Android Indicators:"
        puts "  - ADB Service: #{android_info[:has_adb] ? 'Yes' : 'No'}"
        puts "  - Sync Service: #{android_info[:has_sync] ? 'Yes' : 'No'}"
        puts "  - mDNS Service: #{android_info[:has_mdns] ? 'Yes' : 'No'}"
        puts "  - Android Ports: #{android_info[:android_ports].join(', ')}" if android_info[:android_ports].any?
      end
      
      if result[:os_info][:raw_data][:service_banners].any?
        puts "Service Banners Found:"
        result[:os_info][:raw_data][:service_banners].each do |service, banner|
          puts "  #{service}: #{banner[0..100]}..." if banner.length > 100
          puts "  #{service}: #{banner}" if banner.length <= 100
        end
      end
      puts "-" * 40
    end
  end
end

# Parse command line arguments
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: os_scan.rb [options]"

  opts.on("-n", "--network RANGE", "Network range to scan (e.g., 192.168.1.0/24)") do |n|
    options[:network] = n
  end

  opts.on("-t", "--target IP", "Single IP to scan") do |t|
    options[:target] = t
  end

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit
  end
end.parse!

if options[:target]
  # Single host mode
  scanner = OSScanner.new(options[:target])
  result = scanner.scan
  puts "\nOS Detection Results for #{options[:target]}"
  puts "=" * 50
  puts "Detected OS: #{result[:detected_os]}"
  puts "Confidence Score: #{result[:confidence_score]}"
  puts "\nRaw Data:"
  puts "TTL Analysis: #{result[:raw_data][:ttl_info]}"
  puts "SMB Check: #{result[:raw_data][:smb_info][:details]}"
  if result[:raw_data][:service_banners].any?
    puts "Service Banners:"
    result[:raw_data][:service_banners].each do |service, banner|
      puts "#{service}: #{banner}"
    end
  end
elsif options[:network]
  # Network scanning mode
  scanner = NetworkOSScanner.new(options[:network])
  scanner.scan_network
else
  puts "Please specify either a target IP (-t) or network range (-n)"
  puts "Example: ruby os_scan.rb -n 192.168.1.0/24"
  puts "Example: ruby os_scan.rb -t 192.168.1.100"
end 