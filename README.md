# Security Analysis Tools

A comprehensive collection of Ruby-based security analysis tools for Windows and Android systems. These tools are designed for educational purposes to help understand various aspects of system and mobile security.

## ⚠️ Disclaimer

These tools are for **EDUCATIONAL PURPOSES ONLY**. Only use them on systems you own or have explicit permission to test. Unauthorized security scanning may be illegal and unethical.

## Tools Overview

### 1. Windows Vulnerability Scanner
- System security analysis
- Network vulnerability detection
- Configuration assessment
- Service and software audit

### 2. Android Security Tools
- Wireless security scanner
- Process monitor
- Application security analyzer

## Features

### Windows Security Analysis

- **System Information**
  - Hostname and domain details
  - Windows version analysis
  - Architecture detection
  - User environment analysis

- **Security Policies**
  - Password policy assessment
  - Account lockout settings
  - User privilege analysis

- **Network Security**
  - Open port detection
  - Firewall status verification
  - Network service analysis

- **System Configuration**
  - Service security audit
  - Registry settings analysis
  - User account review
  - Software version checking
  - Antivirus status monitoring

### Android Security Analysis

- **Wireless Security**
  - WiFi network scanning
  - Hotspot configuration analysis
  - Bluetooth security assessment
  - Network vulnerability detection

- **Process Monitoring**
  - Running application detection
  - Service monitoring
  - Resource usage analysis
  - Background process tracking

- **Application Security**
  - Permission analysis
  - Package inspection
  - Security policy verification
  - App vulnerability scanning

## Requirements

### For Windows Analysis
- Ruby 2.7 or higher
- Windows operating system
- Administrative privileges
- Required gems (see Gemfile)

### For Android Analysis
- Ruby 2.7 or higher
- ADB (Android Debug Bridge)
- USB debugging enabled on target device
- Developer options enabled
- Required gems (see Gemfile)

## Installation

1. Clone this repository:
```bash
git clone [repository-url]
cd security-analysis-tools
```

2. Install required gems:
```bash
bundle install
```

## Usage

### Windows Vulnerability Scanner
```bash
ruby windows_vulnerability_scan.rb
```

### Android Security Tools
```bash
# For wireless security scanning
ruby android_wireless_scan.rb

# For process monitoring
ruby android_process_monitor.rb

# For application security analysis
ruby android_security_scan.rb
```

## Tool Outputs

### Windows Scanner Output
1. Console output with color-coded severity levels
2. JSON report file with timestamp
3. Detailed vulnerability descriptions
4. Remediation suggestions

### Android Scanner Output
1. Real-time wireless security status
2. Process activity logs
3. Application security reports
4. Network vulnerability findings

## Security Checks

### Windows Security Checks
- System configuration analysis
- Network security assessment
- Service vulnerability detection
- Registry setting verification
- User account security review
- Software version checking
- Firewall and antivirus status

### Android Security Checks
- Wireless network security
- Bluetooth connection analysis
- Running process inspection
- App permission verification
- Network vulnerability scanning
- System service monitoring
- Security policy compliance

## Output Severity Levels

All vulnerabilities are categorized by severity:
- 🔴 High (Red) - Critical security issues
- 🟡 Medium (Yellow) - Moderate security concerns
- 🔵 Low (Blue) - Minor security considerations

## Best Practices

1. **Windows Analysis**
   - Run with administrative privileges
   - Regular system updates
   - Monitor service configurations
   - Review security policies

2. **Android Analysis**
   - Enable USB debugging only when needed
   - Keep device software updated
   - Monitor app permissions
   - Regular security scans

## Contributing

These are educational tools, and contributions are welcome. Please ensure that any contributions maintain the educational focus of the tools and follow security best practices.

## License

This project is for educational purposes only. Please use responsibly.

## Author

Security Research Team

## Support

For educational purposes only. No official support provided.

## Safety Notes

1. **Windows Scanner**
   - Only run on systems you own/manage
   - Back up important data before scanning
   - Review all findings carefully

2. **Android Scanner**
   - Use only on your personal devices
   - Disable USB debugging after use
   - Monitor device performance during scans
   - Review app permissions regularly 