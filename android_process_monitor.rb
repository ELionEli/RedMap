#!/usr/bin/env ruby

require 'socket'
require 'timeout'
require 'optparse'
require 'json'

class AndroidProcessMonitor
  def initialize(target_ip, timeout = 2)
    @target_ip = target_ip
    @timeout = timeout
    @scan_results = {
      running_apps: [],
      active_services: [],
      system_processes: [],
      network_apps: [],
      media_apps: []
    }
    @common_ports = {
      # Messaging and Social Apps
      5222 => 'Facebook Messenger',
      5223 => 'WhatsApp',
      5228 => 'Google Services',
      8080 => 'Instagram',
      
      # Streaming Apps
      7000 => 'Netflix',
      8008 => 'YouTube',
      8009 => 'Chromecast',
      8443 => 'Spotify',
      
      # Gaming
      3074 => 'Xbox Live/Games',
      3478 => 'PlayStation/Games',
      5060 => 'Gaming Voice Chat',
      
      # Productivity
      993 => 'Email (IMAPS)',
      995 => 'Email (POP3S)',
      6881 => 'File Sharing',
      
      # System Services
      5037 => 'ADB',
      5555 => 'Android Debug',
      8081 => 'Development Server'
    }
  end

  def scan
    puts "\nStarting Android Process Monitor for #{@target_ip}"
    puts "=" * 60
    puts "Educational Process Monitor - For learning purposes only"
    puts "=" * 60

    detect_running_apps
    check_active_services
    monitor_system_processes
    check_network_applications
    detect_media_apps

    display_results
    generate_activity_report
  end

  private

  def check_port(port)
    begin
      Timeout.timeout(@timeout) do
        socket = TCPSocket.new(@target_ip, port)
        banner = socket.recv(1024).strip rescue ""
        socket.close
        return { open: true, banner: banner }
      end
    rescue
      return { open: false, banner: "" }
    end
  end

  def detect_running_apps
    print "\nDetecting Running Applications..."
    
    app_ports = {
      5222 => { name: 'Facebook Messenger', category: 'Social' },
      5223 => { name: 'WhatsApp', category: 'Social' },
      8080 => { name: 'Instagram', category: 'Social' },
      7000 => { name: 'Netflix', category: 'Streaming' },
      8008 => { name: 'YouTube', category: 'Streaming' },
      8443 => { name: 'Spotify', category: 'Music' }
    }

    app_ports.each do |port, info|
      if check_port(port)[:open]
        @scan_results[:running_apps] << {
          name: info[:name],
          category: info[:category],
          port: port,
          status: 'ACTIVE'
        }
      end
    end
    puts " Done"
  end

  def check_active_services
    print "\nAnalyzing Active Services..."
    
    service_ports = {
      5037 => { name: 'Android Debug Bridge', type: 'System' },
      5555 => { name: 'Android Debug Service', type: 'Development' },
      8081 => { name: 'Development Server', type: 'Development' },
      2222 => { name: 'Wireless Debug', type: 'Development' }
    }

    service_ports.each do |port, info|
      if check_port(port)[:open]
        @scan_results[:active_services] << {
          name: info[:name],
          type: info[:type],
          port: port,
          status: 'RUNNING'
        }
      end
    end
    puts " Done"
  end

  def monitor_system_processes
    print "\nMonitoring System Processes..."
    
    system_ports = {
      5554 => 'System UI',
      5555 => 'Activity Manager',
      5556 => 'Package Manager',
      5557 => 'Window Manager'
    }

    system_ports.each do |port, process|
      if check_port(port)[:open]
        @scan_results[:system_processes] << {
          name: process,
          pid: port,  # Using port as pseudo PID for demonstration
          status: 'RUNNING'
        }
      end
    end
    puts " Done"
  end

  def check_network_applications
    print "\nChecking Network Applications..."
    
    network_ports = {
      80 => 'Web Browser',
      443 => 'Secure Browser',
      8080 => 'Alternative Browser',
      53 => 'DNS Client',
      67 => 'DHCP Client'
    }

    network_ports.each do |port, app|
      if check_port(port)[:open]
        @scan_results[:network_apps] << {
          name: app,
          port: port,
          protocol: port == 53 ? 'UDP/TCP' : 'TCP',
          status: 'ACTIVE'
        }
      end
    end
    puts " Done"
  end

  def detect_media_apps
    print "\nDetecting Media Applications..."
    
    media_ports = {
      8008 => { name: 'YouTube', type: 'Video' },
      8009 => { name: 'Chromecast App', type: 'Streaming' },
      8443 => { name: 'Spotify', type: 'Music' },
      7000 => { name: 'Netflix', type: 'Video' },
      6881 => { name: 'Media Sharing', type: 'File Sharing' }
    }

    media_ports.each do |port, info|
      if check_port(port)[:open]
        @scan_results[:media_apps] << {
          name: info[:name],
          type: info[:type],
          port: port,
          status: 'RUNNING'
        }
      end
    end
    puts " Done"
  end

  def display_results
    puts "\nAndroid Process Monitor Results for #{@target_ip}"
    puts "=" * 60

    # Running Applications
    puts "\n1. Running Applications:"
    if @scan_results[:running_apps].empty?
      puts "   No common applications detected"
    else
      @scan_results[:running_apps].each do |app|
        puts "   - #{app[:name]} (#{app[:category]})"
        puts "     Status: #{app[:status]}"
      end
    end

    # Active Services
    puts "\n2. Active Services:"
    if @scan_results[:active_services].empty?
      puts "   No active services detected"
    else
      @scan_results[:active_services].each do |service|
        puts "   - #{service[:name]}"
        puts "     Type: #{service[:type]}"
        puts "     Status: #{service[:status]}"
      end
    end

    # System Processes
    puts "\n3. System Processes:"
    if @scan_results[:system_processes].empty?
      puts "   No system processes detected"
    else
      @scan_results[:system_processes].each do |process|
        puts "   - #{process[:name]}"
        puts "     PID: #{process[:pid]}"
        puts "     Status: #{process[:status]}"
      end
    end

    # Network Applications
    puts "\n4. Network Applications:"
    if @scan_results[:network_apps].empty?
      puts "   No network applications detected"
    else
      @scan_results[:network_apps].each do |app|
        puts "   - #{app[:name]}"
        puts "     Protocol: #{app[:protocol]}"
        puts "     Status: #{app[:status]}"
      end
    end

    # Media Applications
    puts "\n5. Media Applications:"
    if @scan_results[:media_apps].empty?
      puts "   No media applications detected"
    else
      @scan_results[:media_apps].each do |app|
        puts "   - #{app[:name]} (#{app[:type]})"
        puts "     Status: #{app[:status]}"
      end
    end
  end

  def generate_activity_report
    puts "\nActivity Summary Report"
    puts "=" * 60

    total_apps = @scan_results.values.map(&:length).sum
    puts "\nTotal Active Components: #{total_apps}"
    
    puts "\nCategory Breakdown:"
    puts "- Applications: #{@scan_results[:running_apps].length}"
    puts "- Services: #{@scan_results[:active_services].length}"
    puts "- System Processes: #{@scan_results[:system_processes].length}"
    puts "- Network Apps: #{@scan_results[:network_apps].length}"
    puts "- Media Apps: #{@scan_results[:media_apps].length}"

    puts "\nEducational Notes:"
    puts "- This tool demonstrates basic Android process monitoring concepts"
    puts "- It shows how applications use different network ports"
    puts "- Helps understand Android's multi-process architecture"
    puts "- Illustrates system service detection methods"
    puts "- Shows relationship between apps and network activity"
  end
end

# Parse command line arguments
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: android_process_monitor.rb [options]"

  opts.on("-t", "--target IP", "Target Android device IP address") do |t|
    options[:target] = t
  end

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit
  end
end.parse!

if options[:target]
  monitor = AndroidProcessMonitor.new(options[:target])
  monitor.scan
else
  puts "Please specify a target Android device IP address with -t"
  puts "Example: ruby android_process_monitor.rb -t 192.168.1.100"
end 