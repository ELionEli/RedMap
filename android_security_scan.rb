#!/usr/bin/env ruby

require 'socket'
require 'timeout'
require 'optparse'
require 'json'

class AndroidSecurityScanner
  def initialize(target_ip, timeout = 2)
    @target_ip = target_ip
    @timeout = timeout
    @scan_results = {
      adb_security: {},
      open_ports: [],
      debug_status: {},
      network_security: {},
      service_vulnerabilities: {}
    }
  end

  def scan
    puts "\nStarting Android Security Scan for #{@target_ip}"
    puts "=" * 60
    puts "This scanner checks for common security misconfigurations."
    puts "Only use this on devices you own or have permission to test."
    puts "=" * 60

    check_adb_security
    check_common_ports
    check_debug_status
    check_network_security
    check_service_vulnerabilities

    display_results
    generate_recommendations
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

  def check_adb_security
    print "\nChecking ADB (Android Debug Bridge) Security..."
    
    # Check if ADB is enabled and accessible
    adb_result = check_port(5555)
    if adb_result[:open]
      @scan_results[:adb_security] = {
        status: 'WARNING',
        details: 'ADB port is accessible remotely. This could be a security risk.',
        recommendation: 'Disable ADB when not in development use.'
      }
      puts " WARNING!"
    else
      @scan_results[:adb_security] = {
        status: 'SECURE',
        details: 'ADB port is not accessible remotely.',
        recommendation: 'Keep ADB disabled in production.'
      }
      puts " Secure"
    end
  end

  def check_common_ports
    print "\nScanning for commonly exposed ports..."
    
    common_ports = {
      2222 => 'SSH Alternative',
      5555 => 'ADB',
      5037 => 'ADB Control',
      6789 => 'TWRP Backup',
      8080 => 'HTTP Alternative',
      8081 => 'Development Server',
      8888 => 'Development Server',
      9090 => 'Development Server'
    }

    open_ports = []
    common_ports.each do |port, service|
      result = check_port(port)
      if result[:open]
        open_ports << {
          port: port,
          service: service,
          banner: result[:banner]
        }
      end
    end

    @scan_results[:open_ports] = open_ports
    puts " Done"
  end

  def check_debug_status
    print "\nChecking for debug configurations..."
    
    debug_ports = [8000, 8001, 8080, 8081, 8888]
    debug_services = []

    debug_ports.each do |port|
      result = check_port(port)
      if result[:open]
        debug_services << port
      end
    end

    if debug_services.any?
      @scan_results[:debug_status] = {
        status: 'WARNING',
        details: "Debug ports found: #{debug_services.join(', ')}",
        recommendation: 'Close debug ports in production environment'
      }
      puts " WARNING!"
    else
      @scan_results[:debug_status] = {
        status: 'SECURE',
        details: 'No debug ports detected',
        recommendation: 'Continue keeping debug ports closed'
      }
      puts " Secure"
    end
  end

  def check_network_security
    print "\nAnalyzing network security configuration..."
    
    # Check for common network vulnerabilities
    insecure_ports = [23, 21, 2222, 8080]
    exposed_services = []

    insecure_ports.each do |port|
      result = check_port(port)
      if result[:open]
        exposed_services << port
      end
    end

    @scan_results[:network_security] = {
      status: exposed_services.any? ? 'WARNING' : 'SECURE',
      details: exposed_services.any? ? 
        "Potentially insecure services found on ports: #{exposed_services.join(', ')}" :
        'No commonly insecure services detected',
      recommendation: exposed_services.any? ?
        'Consider disabling or securing these services' :
        'Maintain current network security posture'
    }
    puts " #{exposed_services.any? ? 'WARNING!' : 'Secure'}"
  end

  def check_service_vulnerabilities
    print "\nChecking for vulnerable services..."
    
    # List of potentially vulnerable services and their ports
    vulnerable_services = {
      8080 => 'Development Server',
      8888 => 'Exposed Debug Server',
      9090 => 'Development Proxy',
      6789 => 'Backup Service'
    }

    found_vulnerabilities = []

    vulnerable_services.each do |port, service|
      result = check_port(port)
      if result[:open]
        found_vulnerabilities << {
          service: service,
          port: port,
          risk: 'HIGH',
          details: "#{service} exposed to network"
        }
      end
    end

    @scan_results[:service_vulnerabilities] = found_vulnerabilities
    puts " Done"
  end

  def display_results
    puts "\nSecurity Scan Results for #{@target_ip}"
    puts "=" * 60

    # ADB Security
    puts "\n1. ADB Security Status:"
    puts "   Status: #{@scan_results[:adb_security][:status]}"
    puts "   Details: #{@scan_results[:adb_security][:details]}"

    # Open Ports
    puts "\n2. Open Ports:"
    if @scan_results[:open_ports].empty?
      puts "   No potentially risky ports detected"
    else
      @scan_results[:open_ports].each do |port_info|
        puts "   - Port #{port_info[:port]} (#{port_info[:service]})"
      end
    end

    # Debug Status
    puts "\n3. Debug Configuration:"
    puts "   Status: #{@scan_results[:debug_status][:status]}"
    puts "   Details: #{@scan_results[:debug_status][:details]}"

    # Network Security
    puts "\n4. Network Security:"
    puts "   Status: #{@scan_results[:network_security][:status]}"
    puts "   Details: #{@scan_results[:network_security][:details]}"

    # Service Vulnerabilities
    puts "\n5. Service Vulnerabilities:"
    if @scan_results[:service_vulnerabilities].empty?
      puts "   No vulnerable services detected"
    else
      @scan_results[:service_vulnerabilities].each do |vuln|
        puts "   - #{vuln[:service]} (Port #{vuln[:port]})"
        puts "     Risk Level: #{vuln[:risk]}"
        puts "     Details: #{vuln[:details]}"
      end
    end
  end

  def generate_recommendations
    puts "\nSecurity Recommendations:"
    puts "=" * 60

    recommendations = []

    # ADB Recommendations
    if @scan_results[:adb_security][:status] == 'WARNING'
      recommendations << "- Disable ADB when not actively developing"
      recommendations << "- Use USB debugging instead of network debugging when possible"
    end

    # Open Ports Recommendations
    if @scan_results[:open_ports].any?
      recommendations << "- Close unnecessary ports: #{@scan_results[:open_ports].map{|p| p[:port]}.join(', ')}"
      recommendations << "- Use firewalls to restrict access to development ports"
    end

    # Debug Recommendations
    if @scan_results[:debug_status][:status] == 'WARNING'
      recommendations << "- Disable debug mode in production"
      recommendations << "- Remove development servers and debug configurations"
    end

    # Network Security Recommendations
    if @scan_results[:network_security][:status] == 'WARNING'
      recommendations << @scan_results[:network_security][:recommendation]
    end

    # Service Recommendations
    if @scan_results[:service_vulnerabilities].any?
      recommendations << "- Secure or disable vulnerable services"
      recommendations << "- Use encrypted alternatives for necessary services"
    end

    if recommendations.empty?
      puts "\nYour device appears to be well-secured! Continue maintaining current security practices."
    else
      puts "\nRecommended Actions:"
      recommendations.each { |rec| puts rec }
    end
  end
end

# Parse command line arguments
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: android_security_scan.rb [options]"

  opts.on("-t", "--target IP", "Target Android device IP address") do |t|
    options[:target] = t
  end

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit
  end
end.parse!

if options[:target]
  scanner = AndroidSecurityScanner.new(options[:target])
  scanner.scan
else
  puts "Please specify a target Android device IP address with -t"
  puts "Example: ruby android_security_scan.rb -t 192.168.1.100"
end 