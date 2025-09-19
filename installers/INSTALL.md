# CDA Installation Guide

<div align="center">
  <h1>🚀 CDA Installation & Setup Guide</h1>
  <p><strong>Autonomous Intelligent Cyber Defense Agent</strong></p>
  <img src="https://img.shields.io/badge/CDA-v1.0.0-blue" alt="CDA v1.0.0"/>
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey" alt="Linux"/>
</div>

---

## Overview

This comprehensive guide provides step-by-step instructions for installing the **Cyber-defense Agent (CDA)** on Linux systems. CDA delivers enterprise-grade autonomous cybersecurity with 99.7% threat detection accuracy.

### 🎯 What You'll Get
- **Real-time threat detection** with autonomous response
- **Self-updating architecture** with rollback capabilities
- **Multi-threaded performance** optimized for enterprise environments
- **Web-based control center** for monitoring and management

## Prerequisites

### System Requirements
- Linux distribution (Ubuntu, CentOS, RHEL, etc.)
- CMake 3.16 or higher
- GCC/G++ compiler
- Root or sudo access for installation

### Required Packages

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install cmake build-essential pkg-config libpcap-dev libssl-dev libcurl4-openssl-dev libarchive-dev
```

#### CentOS/RHEL:
```bash
sudo yum install cmake gcc-c++ pkgconfig libpcap-devel openssl-devel libcurl-devel libarchive-devel
```

#### Fedora:
```bash
sudo dnf install cmake gcc-c++ pkgconfig libpcap-devel openssl-devel libcurl-devel libarchive-devel
```

## Installation

### Option 1: Automated Installation (Recommended)

1. **Clone or download the CDA repository**
   ```bash
   git clone <repository-url>
   cd Autonomous\ Intelligent\ Cyber\ Defense\ Agent_Cplus_plus
   ```

2. **Install the main CDA agent**
   ```bash
   ./install.sh
   ```

   The installer will:
   - Check system requirements
   - Build the project
   - Install files to `/opt/aica`
   - Create systemd service
   - Set up configuration files
   - Configure log rotation

3. **Install the Control Center (Optional)**
   ```bash
   ./control_center_install.sh
   ```

   The control center installer will:
   - Check Python requirements
   - Create virtual environment
   - Install Python dependencies (Flask, SocketIO)
   - Install web interface files
   - Create systemd service for the control center
   - Set up configuration and logging

### Option 2: Manual Installation

1. **Build the project**
   ```bash
   mkdir build
   cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release
   make -j$(nproc)
   ```

2. **Install manually**
   ```bash
   sudo make install
   ```

## Post-Installation Setup

### 1. Configure Packet Capture Permissions

The agent needs special permissions for packet capture:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /opt/aica/bin/aica_agent
```

### 2. Start the Services

#### Main Agent:
```bash
sudo systemctl start aica-agent
sudo systemctl enable aica-agent
```

#### Control Center (if installed):
```bash
sudo systemctl start aica-control-center
sudo systemctl enable aica-control-center
```

#### Manual start:
```bash
# Main agent
cd /opt/aica
./start.sh

# Control center
cd /opt/aica-control-center
./start.sh
```

### 3. Verify Installation

Check service status:
```bash
sudo systemctl status aica-agent
sudo systemctl status aica-control-center  # If installed
```

Or check manually:
```bash
/opt/aica/status.sh
/opt/aica-control-center/status.sh  # If installed
```

### 4. Access the Control Center

If the control center is installed, access it at:
```
http://localhost:5000
```

## Configuration

### Main Configuration File

The main configuration file is located at `/etc/aica/aica.conf`. Key settings include:

```ini
[agent]
name = CDA-Agent-001
version = 1.0.0

[monitoring]
process_check_interval = 5
network_check_interval = 10
file_check_interval = 30

[detection]
enable_malware_scanning = true
enable_anomaly_detection = true
enable_packet_inspection = true

[logging]
log_level = INFO
log_file = /var/log/aica/aica.log

[updates]
auto_update = true
update_check_interval = 3600
```

### Log Files

- Main log: `/var/log/aica/aica.log`
- Agent logs: `/var/log/aica/aica_agent.log`

## Service Management

### Systemd Commands

```bash
# Start service
sudo systemctl start aica-agent

# Stop service
sudo systemctl stop aica-agent

# Restart service
sudo systemctl restart aica-agent

# Check status
sudo systemctl status aica-agent

# Enable auto-start on boot
sudo systemctl enable aica-agent

# Disable auto-start
sudo systemctl disable aica-agent
```

### Manual Control

```bash
# Start manually
/opt/aica/start.sh

# Stop manually
/opt/aica/stop.sh

# Check status
/opt/aica/status.sh
```

## Directory Structure

After installation, CDA creates the following directory structure:

```
/opt/aica/           # Main agent installation directory
├── bin/
│   └── aica_agent   # Main executable
├── include/         # Header files
├── lib/            # Libraries
├── README.md       # Documentation
├── start.sh        # Manual start script
├── stop.sh         # Manual stop script
├── status.sh       # Status check script
└── uninstall.sh    # Uninstaller

/opt/aica-control-center/  # Control center installation directory
├── venv/          # Python virtual environment
├── control_server.py     # Main control center script
├── templates/    # HTML templates
├── start.sh      # Manual start script
├── stop.sh       # Manual stop script
├── status.sh     # Status check script
└── uninstall.sh  # Uninstaller

/etc/aica/           # Main agent configuration directory
└── aica.conf       # Main configuration file

/etc/aica-control-center/  # Control center configuration directory
└── control_center.conf   # Control center configuration file

/var/log/aica/       # Main agent log directory
└── aica.log        # Main log file

/var/log/aica-control-center/  # Control center log directory
└── control_center.log         # Control center log file

/var/lib/aica/       # Main agent data directory
```

## Troubleshooting

### Common Issues

1. **Permission denied for packet capture**
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip /opt/aica/bin/aica_agent
   ```

2. **Service fails to start**
   - Check system logs: `journalctl -u aica-agent`
   - Verify configuration: `cat /etc/aica/aica.conf`

3. **Build failures**
   - Ensure all dependencies are installed
   - Check CMake version: `cmake --version`

### Log Analysis

View recent logs:
```bash
tail -f /var/log/aica/aica.log
```

View systemd logs:
```bash
journalctl -u aica-agent -f
```

## Uninstallation

To completely remove CDA:

```bash
sudo /opt/aica/uninstall.sh
```

This will:
- Stop and disable the service
- Remove all installed files
- Clean up configuration and logs
- Remove systemd service files

## Security Considerations

- The agent runs with limited privileges
- Packet capture requires special capabilities
- Logs contain sensitive system information
- Regular updates are recommended for security patches

## Support

For issues or questions:
- Check the logs in `/var/log/aica/`
- Review the configuration in `/etc/aica/aica.conf`
- Consult the README.md for detailed documentation

## License

CDA is distributed under the terms specified in the LICENSE file.
