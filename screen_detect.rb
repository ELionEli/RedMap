#!/usr/bin/env ruby

require 'socket'
require 'timeout'
require 'optparse'

class ScreenShareDetector
  def initialize(target_ip, timeout = 2)
    @target_ip = target_ip
    @timeout = timeout
    @results = {
      rdp: { available: false, port: 3389, details: '' },
      vnc: { available: false, port: 5900, details: '' },
      teamviewer: { available: false, port: 5938, details: '' },
      chrome_remote: { available: false, port: 5938, details: '' },
      anydesk: { available: false, port: 7070, details: '' }
    }
  end

  def scan
    puts "\nScanning #{@target_ip} for screen sharing services..."
    puts "=" * 60

    check_rdp
    check_vnc
    check_teamviewer
    check_chrome_remote
    check_anydesk
    
    display_results
  end

  private

  def check_port(port)
    begin
      Timeout.timeout(@timeout) do
        socket = TCPSocket.new(@target_ip, port)
        socket.close
        return true
      end
    rescue
      return false
    end
  end

  def check_rdp
    print "Checking RDP (Remote Desktop Protocol)..."
    if check_port(3389)
      @results[:rdp][:available] = true
      @results[:rdp][:details] = 'RDP port is open. Remote Desktop might be enabled.'
      puts " Found!"
    else
      puts " Not found"
    end
  end

  def check_vnc
    print "Checking VNC (Virtual Network Computing)..."
    # Check common VNC ports (5900-5903)
    vnc_ports = (5900..5903)
    open_vnc_ports = []

    vnc_ports.each do |port|
      if check_port(port)
        open_vnc_ports << port
      end
    end

    if open_vnc_ports.any?
      @results[:vnc][:available] = true
      @results[:vnc][:details] = "VNC ports open: #{open_vnc_ports.join(', ')}"
      puts " Found!"
    else
      puts " Not found"
    end
  end

  def check_teamviewer
    print "Checking TeamViewer..."
    if check_port(5938)
      @results[:teamviewer][:available] = true
      @results[:teamviewer][:details] = 'TeamViewer port detected'
      puts " Found!"
    else
      puts " Not found"
    end
  end

  def check_chrome_remote
    print "Checking Chrome Remote Desktop..."
    if check_port(5938) || check_port(5939)
      @results[:chrome_remote][:available] = true
      @results[:chrome_remote][:details] = 'Chrome Remote Desktop ports detected'
      puts " Found!"
    else
      puts " Not found"
    end
  end

  def check_anydesk
    print "Checking AnyDesk..."
    if check_port(7070)
      @results[:anydesk][:available] = true
      @results[:anydesk][:details] = 'AnyDesk port detected'
      puts " Found!"
    else
      puts " Not found"
    end
  end

  def display_results
    puts "\nScreen Sharing Service Detection Results for #{@target_ip}"
    puts "=" * 60

    found_services = false

    @results.each do |service, info|
      if info[:available]
        found_services = true
        puts "\n#{service.to_s.upcase} Service Detected:"
        puts "  Port: #{info[:port]}"
        puts "  Details: #{info[:details]}"
      end
    end

    if !found_services
      puts "\nNo screen sharing services were detected."
      puts "Note: Services might still be running on non-standard ports"
      puts "or might be protected by a firewall."
    end

    puts "\nSecurity Recommendations:"
    puts "- Ensure all remote access services are properly secured"
    puts "- Use strong passwords and 2FA where possible"
    puts "- Consider disabling unused remote access services"
    puts "- Monitor these ports for unauthorized access attempts"
  end
end

# Parse command line arguments
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: screen_detect.rb [options]"

  opts.on("-t", "--target IP", "Target IP address to scan") do |t|
    options[:target] = t
  end

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit
  end
end.parse!

if options[:target]
  detector = ScreenShareDetector.new(options[:target])
  detector.scan
else
  puts "Please specify a target IP address with -t"
  puts "Example: ruby screen_detect.rb -t 192.168.1.100"
end 