# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with CDA.

## Quick Diagnostics

### System Status Check

```bash
# Check if CDA is running
ps aux | grep cda_agent

# Check system resources
top -p $(pgrep cda_agent)

# Check network interfaces
ip link show

# Check disk space
df -h

# Check system logs
journalctl -u aica -f
```

### Log Analysis

```bash
# View recent logs
tail -f /var/log/cda/agent.log

# Search for errors
grep "ERROR" /var/log/cda/agent.log

# Check packet inspector logs
tail -f /var/log/cda/packet_inspector.log
```

## Common Issues and Solutions

### Installation Issues

#### Build Fails with CMake

**Symptoms:**
- CMake configuration fails
- Missing dependencies error

**Solutions:**
```bash
# Install missing dependencies
sudo apt update
sudo apt install libpcap-dev libcurl4-openssl-dev libarchive-dev

# Clean build directory
rm -rf build/
mkdir build && cd build

# Reconfigure with verbose output
cmake -DCMAKE_VERBOSE_MAKEFILE=ON ..
```

#### Compiler Errors

**Symptoms:**
- C++ compilation errors
- Header file not found

**Solutions:**
```bash
# Check compiler version
g++ --version

# Ensure C++17 support
g++ -std=c++17 -c src/agent/main.cpp

# Check include paths
pkg-config --cflags libpcap
```

### Runtime Issues

#### Agent Won't Start

**Symptoms:**
- Agent exits immediately
- "Permission denied" errors

**Solutions:**
```bash
# Check permissions
ls -la cda_agent

# Run with root privileges for packet capture
sudo ./cda_agent

# Check configuration file
cat cda_config.txt

# Validate configuration
./cda_agent --validate-config
```

#### Packet Capture Fails

**Symptoms:**
- "No suitable device found" error
- "Permission denied" for network interface

**Solutions:**
```bash
# List available interfaces
ip link show

# Check interface permissions
sudo setcap cap_net_raw,cap_net_admin=eip ./cda_agent

# Test packet capture manually
sudo tcpdump -i eth0 -c 1

# Check libpcap installation
ldd ./cda_agent | grep pcap
```

#### High CPU Usage

**Symptoms:**
- Agent consumes excessive CPU
- System becomes unresponsive

**Solutions:**
```bash
# Check monitoring configuration
cat cda_config.txt | grep -A 5 performance

# Reduce packet buffer size
sed -i 's/packet_buffer_size=.*/packet_buffer_size=32768/' cda_config.txt

# Adjust monitoring intervals
sed -i 's/monitoring_interval=.*/monitoring_interval=5000/' cda_config.txt

# Restart agent
sudo systemctl restart aica
```

#### Memory Leaks

**Symptoms:**
- Memory usage continuously increases
- System runs out of memory

**Solutions:**
```bash
# Monitor memory usage
top -p $(pgrep cda_agent)

# Check for memory leaks with Valgrind
valgrind --leak-check=full ./cda_agent --test

# Reduce buffer sizes
sed -i 's/buffer_size=.*/buffer_size=1048576/' cda_config.txt

# Enable memory profiling
export MALLOC_CHECK_=2
```

### Network Issues

#### No Network Traffic Detected

**Symptoms:**
- Packet inspector shows no packets
- Network monitoring appears inactive

**Solutions:**
```bash
# Verify interface is up
ip link show eth0

# Check interface statistics
ip -s link show eth0

# Test with tcpdump
sudo tcpdump -i eth0 -c 10

# Check firewall rules
sudo iptables -L

# Verify interface in promiscuous mode
ip link show eth0 | grep PROMISC
```

#### False Positive Alerts

**Symptoms:**
- Too many security alerts
- Legitimate traffic flagged as suspicious

**Solutions:**
```bash
# Adjust detection sensitivity
sed -i 's/sensitivity=.*/sensitivity=MEDIUM/' cda_config.txt

# Update whitelist
echo "192.168.1.100" >> whitelist.txt

# Review detection rules
cat detection_rules.txt

# Fine-tune thresholds
sed -i 's/threat_threshold=.*/threat_threshold=0.8/' cda_config.txt
```

### Configuration Issues

#### Configuration Not Loading

**Symptoms:**
- Settings not applied
- "Configuration file not found" error

**Solutions:**
```bash
# Check file location
ls -la cda_config.txt

# Validate syntax
python -c "import configparser; c=configparser.ConfigParser(); c.read('cda_config.txt'); print('Valid')"

# Check file permissions
chmod 644 cda_config.txt

# Specify config path explicitly
./cda_agent --config /path/to/cda_config.txt
```

#### Invalid Configuration Values

**Symptoms:**
- Agent starts but behaves unexpectedly
- Warning messages about invalid values

**Solutions:**
```bash
# Validate configuration
./cda_agent --validate-config cda_config.txt

# Check for typos
grep -n "=" cda_config.txt

# Compare with example config
diff cda_config.txt config/aica_config.example.txt

# Reset to defaults
cp config/aica_config.default.txt cda_config.txt
```

### Update Issues

#### Update Download Fails

**Symptoms:**
- Update check fails
- "Connection refused" errors

**Solutions:**
```bash
# Check network connectivity
ping update.cda-agent.com

# Verify proxy settings
echo $http_proxy

# Check DNS resolution
nslookup update.cda-agent.com

# Test with curl
curl -I https://update.cda-agent.com/latest

# Update manually
wget https://update.cda-agent.com/latest/cda_agent.tar.gz
```

#### Update Installation Fails

**Symptoms:**
- Update downloads but won't install
- "Verification failed" errors

**Solutions:**
```bash
# Check disk space
df -h /opt/cda

# Verify file integrity
sha256sum cda_agent.tar.gz

# Check permissions
ls -la /opt/cda

# Install manually
tar -xzf cda_agent.tar.gz -C /opt/cda
```

### Performance Issues

#### Slow Response Times

**Symptoms:**
- Delayed threat detection
- High latency in monitoring

**Solutions:**
```bash
# Optimize thread count
sed -i 's/max_threads=.*/max_threads=8/' cda_config.txt

# Increase buffer sizes
sed -i 's/buffer_size=.*/buffer_size=4194304/' cda_config.txt

# Enable caching
sed -i 's/enable_cache=.*/enable_cache=true/' cda_config.txt

# Profile performance
perf record -p $(pgrep cda_agent) -g
```

#### Database Performance

**Symptoms:**
- Slow query responses
- High I/O wait

**Solutions:**
```bash
# Check database size
du -sh /var/lib/cda/database/

# Optimize queries
EXPLAIN QUERY PLAN SELECT * FROM threats;

# Add indexes
CREATE INDEX idx_threats_timestamp ON threats(timestamp);

# Vacuum database
sqlite3 /var/lib/cda/database/aica.db "VACUUM;"
```

### Security Issues

#### Authentication Failures

**Symptoms:**
- Cannot access web interface
- API calls rejected

**Solutions:**
```bash
# Check authentication settings
cat cda_config.txt | grep -A 5 auth

# Reset admin password
./cda_agent --reset-password admin

# Verify SSL certificates
openssl x509 -in /etc/cda/ssl/cert.pem -text

# Check firewall rules
sudo ufw status
```

#### SSL/TLS Issues

**Symptoms:**
- HTTPS connections fail
- Certificate validation errors

**Solutions:**
```bash
# Check certificate validity
openssl x509 -in /etc/cda/ssl/cert.pem -checkend 0

# Verify certificate chain
openssl verify -CAfile /etc/cda/ssl/ca.pem /etc/cda/ssl/cert.pem

# Regenerate certificates
./cda_agent --generate-cert

# Update cipher suites
sed -i 's/cipher_suites=.*/cipher_suites=HIGH:!aNULL:!MD5/' cda_config.txt
```

## Advanced Troubleshooting

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
# Start with debug logging
./cda_agent --log-level DEBUG --verbose

# Enable core dumps
ulimit -c unlimited
echo "/var/crash/core.%e.%p.%t" > /proc/sys/kernel/core_pattern

# Attach debugger
gdb ./cda_agent $(pgrep cda_agent)
```

### Packet Analysis

Analyze network packets for issues:

```bash
# Capture packets for analysis
sudo tcpdump -i eth0 -w capture.pcap -c 1000

# Analyze with Wireshark
wireshark capture.pcap

# Check packet statistics
tcpdump -i eth0 -c 100 -q | awk '{print $3}' | sort | uniq -c | sort -nr
```

### System Integration

Check integration with system components:

```bash
# Verify systemd integration
systemctl status aica

# Check log rotation
logrotate -f /etc/logrotate.d/aica

# Verify cron jobs
crontab -l | grep aica

# Check SELinux/AppArmor
sudo aa-status | grep aica
```


### Diagnostic Information

When reporting issues, include:

```bash
# System information
uname -a
lsb_release -a

# CDA version
./cda_agent --version

# Configuration (redact sensitive data)
cat cda_config.txt | grep -v password

# Recent logs
tail -100 /var/log/cda/agent.log

# Process information
ps aux | grep aica
```

### Emergency Procedures

For critical issues:

1. **Stop the agent**: `sudo systemctl stop aica`
2. **Isolate the system**: Disconnect from network if compromised
3. **Collect evidence**: Preserve logs and system state
4. **Contact support**: Provide diagnostic information
5. **Restore from backup**: If system integrity is compromised

## Prevention

### Best Practices

- Keep CDA updated
- Monitor system resources regularly
- Review logs daily
- Test configurations in staging
- Maintain backups
- Use monitoring tools (Nagios, Zabbix)

### Maintenance Schedule

- **Daily**: Check logs and alerts
- **Weekly**: Review performance metrics
- **Monthly**: Update software and review configurations
- **Quarterly**: Test disaster recovery procedures
- **Annually**: Review and update security policies
