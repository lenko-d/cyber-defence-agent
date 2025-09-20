# User Guide

This guide covers installation, configuration, and usage of CDA.

## Installation

### Prerequisites

- Linux (Ubuntu 20.04+ recommended)
- CMake 3.16+
- C++17 compatible compiler (GCC 7+ or Clang 5+)
- Python 3.8+
- Root privileges for packet capture

### System Dependencies

```bash
sudo apt update
sudo apt install libpcap-dev libcurl4-openssl-dev libarchive-dev
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-repo/cda-agent.git
cd cda-agent

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the project
make

# Optional: Install system-wide
sudo make install
```

### Python Backend Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Configure LLM backend
cd src/backend
python llm_backend.py --setup
```

## Configuration

### Basic Configuration

Create `cda_config.txt` in the working directory:

```ini
[general]
log_level=INFO
update_interval=3600

[network]
interface=eth0
packet_buffer_size=65536

[detection]
sensitivity=HIGH
quarantine_path=/var/quarantine

[llm]
backend_url=http://localhost:5000
model=gpt-3.5-turbo
```

### Network Interface Selection

To list available network interfaces:

```bash
ip link show
```

Common interfaces:
- `eth0` - Ethernet
- `wlan0` - Wireless
- `lo` - Loopback (for testing)

### Security Considerations

- Run CDA with minimal privileges
- Use dedicated user account
- Configure firewall rules appropriately
- Enable logging and monitoring

## Running CDA

### Basic Startup

```bash
# Start with default configuration
sudo ./cda_agent

# Start with custom config
sudo ./cda_agent --config /path/to/config.txt

# Run in test mode (no root required)
./cda_agent --no-root --test
```

### Command Line Options

- `--config <file>` - Specify configuration file
- `--interface <iface>` - Network interface to monitor
- `--no-root` - Run without root privileges (limited functionality)
- `--test` - Enable test mode
- `--verbose` - Enable verbose logging
- `--help` - Show help message

### Service Mode

To run CDA as a system service:

```bash
# Create service file
sudo cp cda.service /etc/systemd/system/

# Enable and start service
sudo systemctl enable cda
sudo systemctl start cda

# Check status
sudo systemctl status cda
```

## Monitoring and Control

### HTTP Interface

CDA provides a web interface on port 8080 by default.

#### Status Endpoint

```bash
curl http://localhost:8080/status
```

Response:
```json
{
  "status": "running",
  "uptime": "2h 30m",
  "threats_detected": 5,
  "packets_processed": 125000,
  "cpu_usage": 3.2,
  "memory_usage": 45.8
}
```

#### Command Endpoint

```bash
curl -X POST http://localhost:8080/command -d "restart"
```

#### Logs Endpoint

```bash
curl http://localhost:8080/logs
```

### Log Files

CDA logs are stored in:
- `/var/log/cda/agent.log` - Main agent logs
- `/var/log/cda/packet_inspector.log` - Packet inspection logs
- `/var/log/cda/updates.log` - Update operation logs

## Threat Response

### Automatic Responses

CDA can automatically respond to detected threats:

- **Quarantine**: Isolate suspicious files
- **Block**: Add firewall rules to block malicious IPs
- **Alert**: Send notifications to administrators
- **Log**: Record all security events

### Manual Intervention

For manual control:

```bash
# View current threats
curl http://localhost:8080/threats

# Quarantine a specific file
curl -X POST http://localhost:8080/quarantine -d "/path/to/suspicious/file"

# Block an IP address
curl -X POST http://localhost:8080/block -d "192.168.1.100"
```

## Updates

### Automatic Updates

CDA checks for updates automatically based on configuration.

### Manual Update Check

```bash
# Check for updates
curl -X POST http://localhost:8080/command -d "check_updates"

# View available updates
curl http://localhost:8080/updates
```

### Update Process

1. Download update package
2. Verify integrity
3. Create backup
4. Install update
5. Restart services
6. Verify functionality

## Troubleshooting

### Common Issues

#### Packet Capture Fails

- Ensure running with root privileges
- Check network interface permissions
- Verify libpcap installation

#### High CPU Usage

- Adjust packet buffer size
- Reduce monitoring sensitivity
- Check for infinite loops in detection logic

#### Memory Leaks

- Monitor memory usage with `htop`
- Check for unclosed file handles
- Review thread management

### Debug Mode

Enable debug logging:

```ini
[general]
log_level=DEBUG
```

### Performance Tuning

```ini
[performance]
max_threads=4
buffer_size=32768
detection_timeout=5000
```

## Security Best Practices

- Keep CDA updated
- Use strong authentication for HTTP interface
- Monitor logs regularly
- Configure appropriate firewall rules
- Use dedicated network interface for monitoring
- Enable encryption for all communications
