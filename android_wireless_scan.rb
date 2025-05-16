#!/usr/bin/env ruby

require 'socket'
require 'timeout'
require 'optparse'
require 'json'

class AndroidWirelessScanner
  def initialize(target_ip, timeout = 2)
    @target_ip = target_ip
    @timeout = timeout
    @scan_results = {
      wireless_security: {},
      hotspot_config: {},
      bluetooth_status: {},
      app_permissions: {},
      network_vulnerabilities: {},
      wifi_protocols: {}
    }
  end

  def scan
    puts "\nStarting Android Wireless Security Analysis for #{@target_ip}"
    puts "=" * 60
    puts "Educational Security Scanner - Use only on devices you own"
    puts "=" * 60

    check_wireless_security
    check_hotspot_configuration
    check_bluetooth_security
    analyze_app_permissions
    check_network_vulnerabilities
    check_wifi_protocols

    display_results
    generate_security_report
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

  def check_wireless_security
    print "\nAnalyzing Wireless Security Configuration..."
    
    # Check for common wireless vulnerabilities
    wireless_ports = {
      1723 => 'PPTP VPN',
      2049 => 'NFS',
      5353 => 'mDNS',
      8080 => 'HTTP Proxy',
      8081 => 'HTTP Alt',
      10123 => 'Network Discovery'
    }

    findings = []
    wireless_ports.each do |port, service|
      if check_port(port)[:open]
        findings << {
          service: service,
          risk_level: 'HIGH',
          details: "#{service} exposed on port #{port}"
        }
      end
    end

    @scan_results[:wireless_security] = {
      status: findings.any? ? 'VULNERABLE' : 'SECURE',
      findings: findings,
      recommendations: [
        'Disable unnecessary wireless services',
        'Use WPA3 encryption for WiFi',
        'Enable MAC address filtering',
        'Disable SSID broadcast when not needed'
      ]
    }
    puts " Done"
  end

  def check_hotspot_configuration
    print "\nChecking Hotspot Security..."
    
    hotspot_ports = [8080, 8081, 8082]  # Common Android hotspot ports
    exposed_services = []

    hotspot_ports.each do |port|
      if check_port(port)[:open]
        exposed_services << port
      end
    end

    @scan_results[:hotspot_config] = {
      status: exposed_services.any? ? 'VULNERABLE' : 'SECURE',
      exposed_ports: exposed_services,
      recommendations: [
        'Use WPA3 for hotspot security',
        'Change default hotspot password regularly',
        'Limit number of connected devices',
        'Disable hotspot when not in use'
      ]
    }
    puts " Done"
  end

  def check_bluetooth_security
    print "\nAnalyzing Bluetooth Security..."
    
    # Check common Bluetooth service ports
    bluetooth_ports = [
      2000,  # Bluetooth File Transfer
      2001,  # Bluetooth Control
      2002   # Bluetooth Audio
    ]

    exposed_bt_services = []
    bluetooth_ports.each do |port|
      if check_port(port)[:open]
        exposed_bt_services << port
      end
    end

    @scan_results[:bluetooth_status] = {
      status: exposed_bt_services.any? ? 'VULNERABLE' : 'SECURE',
      exposed_services: exposed_bt_services,
      recommendations: [
        'Disable Bluetooth when not in use',
        'Use Bluetooth 5.0 or higher',
        'Avoid pairing devices in public places',
        'Regularly unpair unused devices'
      ]
    }
    puts " Done"
  end

  def analyze_app_permissions
    print "\nScanning App Permissions..."
    
    # Common sensitive Android permissions to check
    sensitive_permissions = {
      location_services: check_port(8084)[:open],
      camera_access: check_port(8085)[:open],
      microphone_access: check_port(8086)[:open],
      storage_access: check_port(8087)[:open],
      contacts_access: check_port(8088)[:open]
    }

    risky_permissions = []
    sensitive_permissions.each do |permission, is_open|
      if is_open
        risky_permissions << permission
      end
    end

    @scan_results[:app_permissions] = {
      status: risky_permissions.any? ? 'WARNING' : 'SECURE',
      exposed_permissions: risky_permissions,
      recommendations: [
        'Review app permissions regularly',
        'Revoke unnecessary permissions',
        'Use app permission manager',
        'Install apps only from trusted sources'
      ]
    }
    puts " Done"
  end

  def check_network_vulnerabilities
    print "\nChecking Network Vulnerabilities..."
    
    vulnerable_ports = {
      21 => 'FTP',
      23 => 'Telnet',
      2222 => 'Alternative SSH',
      5555 => 'ADB',
      8888 => 'Alternative HTTP'
    }

    found_vulnerabilities = []
    vulnerable_ports.each do |port, service|
      if check_port(port)[:open]
        found_vulnerabilities << {
          port: port,
          service: service,
          risk: 'HIGH',
          mitigation: "Disable #{service} if not required"
        }
      end
    end

    @scan_results[:network_vulnerabilities] = {
      status: found_vulnerabilities.any? ? 'VULNERABLE' : 'SECURE',
      findings: found_vulnerabilities,
      recommendations: [
        'Use VPN when on public networks',
        'Disable unnecessary network services',
        'Keep system updated',
        'Use network firewall'
      ]
    }
    puts " Done"
  end

  def check_wifi_protocols
    print "\nAnalyzing WiFi Protocol Security..."
    
    # Check for common WiFi protocol vulnerabilities
    wifi_ports = {
      53 => 'DNS',
      67 => 'DHCP',
      137 => 'NetBIOS',
      161 => 'SNMP',
      1900 => 'UPnP'
    }

    exposed_protocols = []
    wifi_ports.each do |port, protocol|
      if check_port(port)[:open]
        exposed_protocols << {
          protocol: protocol,
          port: port,
          recommendation: "Secure or disable #{protocol}"
        }
      end
    end

    @scan_results[:wifi_protocols] = {
      status: exposed_protocols.any? ? 'WARNING' : 'SECURE',
      exposed_protocols: exposed_protocols,
      recommendations: [
        'Use latest WiFi security protocols',
        'Disable WPS',
        'Enable WiFi encryption',
        'Use strong WiFi passwords'
      ]
    }
    puts " Done"
  end

  def display_results
    puts "\nWireless Security Analysis Results for #{@target_ip}"
    puts "=" * 60

    # Wireless Security
    puts "\n1. Wireless Security Status:"
    puts "   Status: #{@scan_results[:wireless_security][:status]}"
    if @scan_results[:wireless_security][:findings].any?
      puts "   Findings:"
      @scan_results[:wireless_security][:findings].each do |finding|
        puts "   - #{finding[:service]}: #{finding[:details]}"
      end
    end

    # Hotspot Configuration
    puts "\n2. Hotspot Security:"
    puts "   Status: #{@scan_results[:hotspot_config][:status]}"
    if @scan_results[:hotspot_config][:exposed_ports].any?
      puts "   Exposed Ports: #{@scan_results[:hotspot_config][:exposed_ports].join(', ')}"
    end

    # Bluetooth Security
    puts "\n3. Bluetooth Security:"
    puts "   Status: #{@scan_results[:bluetooth_status][:status]}"
    if @scan_results[:bluetooth_status][:exposed_services].any?
      puts "   Exposed Services: #{@scan_results[:bluetooth_status][:exposed_services].join(', ')}"
    end

    # App Permissions
    puts "\n4. App Permissions Analysis:"
    puts "   Status: #{@scan_results[:app_permissions][:status]}"
    if @scan_results[:app_permissions][:exposed_permissions].any?
      puts "   Risky Permissions Detected:"
      @scan_results[:app_permissions][:exposed_permissions].each do |perm|
        puts "   - #{perm.to_s.gsub('_', ' ').capitalize}"
      end
    end

    # Network Vulnerabilities
    puts "\n5. Network Vulnerabilities:"
    if @scan_results[:network_vulnerabilities][:findings].any?
      puts "   Found Vulnerabilities:"
      @scan_results[:network_vulnerabilities][:findings].each do |vuln|
        puts "   - #{vuln[:service]} (Port #{vuln[:port]})"
        puts "     Risk Level: #{vuln[:risk]}"
        puts "     Mitigation: #{vuln[:mitigation]}"
      end
    else
      puts "   No major vulnerabilities detected"
    end

    # WiFi Protocols
    puts "\n6. WiFi Protocol Security:"
    puts "   Status: #{@scan_results[:wifi_protocols][:status]}"
    if @scan_results[:wifi_protocols][:exposed_protocols].any?
      puts "   Exposed Protocols:"
      @scan_results[:wifi_protocols][:exposed_protocols].each do |proto|
        puts "   - #{proto[:protocol]} (Port #{proto[:port]})"
      end
    end
  end

  def generate_security_report
    puts "\nSecurity Recommendations:"
    puts "=" * 60

    all_recommendations = []

    # Collect all recommendations
    @scan_results.each do |category, data|
      if data[:recommendations]
        puts "\n#{category.to_s.gsub('_', ' ').capitalize} Recommendations:"
        data[:recommendations].each do |rec|
          puts "- #{rec}"
        end
      end
    end

    puts "\nEducational Notes:"
    puts "- This scan is for educational purposes only"
    puts "- Always obtain proper authorization before scanning"
    puts "- Keep your Android system and apps updated"
    puts "- Use strong authentication methods"
    puts "- Regular security audits are recommended"
  end
end

# Parse command line arguments
options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: android_wireless_scan.rb [options]"

  opts.on("-t", "--target IP", "Target Android device IP address") do |t|
    options[:target] = t
  end

  opts.on("-h", "--help", "Show this help message") do
    puts opts
    exit
  end
end.parse!

if options[:target]
  scanner = AndroidWirelessScanner.new(options[:target])
  scanner.scan
else
  puts "Please specify a target Android device IP address with -t"
  puts "Example: ruby android_wireless_scan.rb -t 192.168.1.100"
end 