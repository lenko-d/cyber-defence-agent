#!/bin/bash

# CDA (Cyber-defense Agent) Installer
# This script builds and installs the CDA system on Linux systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/cda"
CONFIG_DIR="/etc/cda"
LOG_DIR="/var/log/cda"
DATA_DIR="/var/lib/cda"
SERVICE_NAME="cda-agent"
BUILD_DIR="build"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."

    # Check for required commands
    local required_commands=("cmake" "make" "g++" "pkg-config" "sudo")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "Required command '$cmd' not found. Please install it first."
            exit 1
        fi
    done

    # Check for required libraries
    local required_libs=("libpcap" "libssl" "libcrypto")
    for lib in "${required_libs[@]}"; do
        if ! pkg-config --exists "$lib"; then
            print_error "Required library '$lib' not found. Please install development packages."
            print_error "For Ubuntu/Debian: sudo apt-get install libpcap-dev libssl-dev"
            print_error "For CentOS/RHEL: sudo yum install libpcap-devel openssl-devel"
            exit 1
        fi
    done

    print_success "System requirements check passed"
}

# Function to create directories
create_directories() {
    print_status "Creating installation directories..."

    sudo mkdir -p "$INSTALL_DIR"
    sudo mkdir -p "$CONFIG_DIR"
    sudo mkdir -p "$LOG_DIR"
    sudo mkdir -p "$DATA_DIR"

    # Set proper permissions
    sudo chown -R "$USER:$USER" "$INSTALL_DIR"
    sudo chown -R "$USER:$USER" "$CONFIG_DIR"
    sudo chown -R "$USER:$USER" "$LOG_DIR"
    sudo chown -R "$USER:$USER" "$DATA_DIR"

    print_success "Directories created successfully"
}

# Function to build the project
build_project() {
    print_status "Building CDA project..."

    # Clean previous build
    if [[ -d "$BUILD_DIR" ]]; then
        rm -rf "$BUILD_DIR"
    fi

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Configure with CMake
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"

    # Build
    make -j$(nproc)

    print_success "Project built successfully"
    cd ..
}

# Function to install files
install_files() {
    print_status "Installing CDA files..."

    cd "$BUILD_DIR"

    # Install using CMake
    make install

    cd ..

    # Copy additional files
    if [[ -f "README.md" ]]; then
        cp README.md "$INSTALL_DIR/"
    fi

    if [[ -f "LICENSE" ]]; then
        cp LICENSE "$INSTALL_DIR/"
    fi

    print_success "Files installed successfully"
}

# Function to create configuration files
create_config() {
    print_status "Creating configuration files..."

    # Create default configuration
    cat > "$CONFIG_DIR/cda.conf" << EOF
# CDA Configuration File
# This file contains configuration settings for the CDA agent

[agent]
# Agent identification
name = CDA-Agent-001
version = 1.0.0

[monitoring]
# Monitoring intervals (in seconds)
process_check_interval = 5
network_check_interval = 10
file_check_interval = 30

[detection]
# Detection settings
enable_malware_scanning = true
enable_anomaly_detection = true
enable_packet_inspection = true

[logging]
# Logging configuration
log_level = INFO
log_file = $LOG_DIR/cda.log
max_log_size = 100MB
max_log_files = 5

[updates]
# Update configuration
auto_update = true
update_check_interval = 3600
update_server = https://updates.cda.example.com

[security]
# Security settings
enable_self_defense = true
enable_safe_mode = true
max_concurrent_actions = 5
EOF

    print_success "Configuration files created"
}

# Function to create systemd service
create_service() {
    print_status "Creating systemd service..."

    sudo tee "/etc/systemd/system/$SERVICE_NAME.service" > /dev/null << EOF
[Unit]
Description=Cyber-defense Agent (CDA)
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
Group=$USER
ExecStart=$INSTALL_DIR/bin/cda_agent
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cda-agent

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR $DATA_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Resource limits
MemoryLimit=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    print_success "Systemd service created"
}

# Function to create startup scripts
create_scripts() {
    print_status "Creating utility scripts..."

    # Create start script
    cat > "$INSTALL_DIR/start.sh" << 'EOF'
#!/bin/bash
# CDA Start Script

echo "Starting CDA Agent..."
cd /opt/cda
./bin/cda_agent &
echo $! > cda.pid
echo "CDA Agent started with PID $(cat cda.pid)"
EOF

    # Create stop script
    cat > "$INSTALL_DIR/stop.sh" << 'EOF'
#!/bin/bash
# CDA Stop Script

if [[ -f "/opt/cda/cda.pid" ]]; then
    PID=$(cat /opt/cda/cda.pid)
    echo "Stopping CDA Agent (PID: $PID)..."
    kill $PID
    rm -f /opt/cda/cda.pid
    echo "CDA Agent stopped"
else
    echo "CDA Agent does not appear to be running"
fi
EOF

    # Create status script
    cat > "$INSTALL_DIR/status.sh" << 'EOF'
#!/bin/bash
# CDA Status Script

if [[ -f "/opt/cda/cda.pid" ]]; then
    PID=$(cat /opt/cda/cda.pid)
    if ps -p $PID > /dev/null; then
        echo "CDA Agent is running (PID: $PID)"
        echo "Memory usage:"
        ps -p $PID -o pid,ppid,cmd,%mem,%cpu --no-headers
    else
        echo "CDA Agent is not running (stale PID file)"
        rm -f /opt/cda/cda.pid
    fi
else
    echo "CDA Agent is not running"
fi

# Show recent log entries
echo ""
echo "Recent log entries:"
tail -n 10 /var/log/cda/cda.log 2>/dev/null || echo "No log file found"
EOF

    # Make scripts executable
    chmod +x "$INSTALL_DIR/start.sh"
    chmod +x "$INSTALL_DIR/stop.sh"
    chmod +x "$INSTALL_DIR/status.sh"

    print_success "Utility scripts created"
}

# Function to set up log rotation
setup_logrotate() {
    print_status "Setting up log rotation..."

    sudo tee "/etc/logrotate.d/cda" > /dev/null << EOF
/var/log/cda/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 $USER $USER
    postrotate
        systemctl reload cda-agent
    endscript
}
EOF

    print_success "Log rotation configured"
}

# Function to create uninstaller
create_uninstaller() {
    print_status "Creating uninstaller..."

    cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
# CDA Uninstaller

echo "Stopping CDA service..."
sudo systemctl stop cda-agent 2>/dev/null || true
sudo systemctl disable cda-agent 2>/dev/null || true

echo "Removing systemd service..."
sudo rm -f /etc/systemd/system/cda-agent.service
sudo systemctl daemon-reload

echo "Removing files..."
sudo rm -rf /opt/cda
sudo rm -rf /etc/cda
sudo rm -rf /var/log/cda
sudo rm -rf /var/lib/cda
sudo rm -f /etc/logrotate.d/cda

echo "CDA has been uninstalled successfully"
EOF

    chmod +x "$INSTALL_DIR/uninstall.sh"

    print_success "Uninstaller created"
}

# Function to display post-installation information
post_install_info() {
    print_success "CDA installation completed successfully!"
    echo ""
    echo "Installation Summary:"
    echo "====================="
    echo "Install Directory: $INSTALL_DIR"
    echo "Config Directory: $CONFIG_DIR"
    echo "Log Directory: $LOG_DIR"
    echo "Data Directory: $DATA_DIR"
    echo ""
    echo "Service Management:"
    echo "=================="
    echo "Start service:   sudo systemctl start cda-agent"
    echo "Stop service:    sudo systemctl stop cda-agent"
    echo "Enable service:  sudo systemctl enable cda-agent"
    echo "Check status:    sudo systemctl status cda-agent"
    echo ""
    echo "Manual Control:"
    echo "=============="
    echo "Start manually:  $INSTALL_DIR/start.sh"
    echo "Stop manually:   $INSTALL_DIR/stop.sh"
    echo "Check status:    $INSTALL_DIR/status.sh"
    echo ""
    echo "Configuration:"
    echo "=============="
    echo "Config file:     $CONFIG_DIR/cda.conf"
    echo "Log files:       $LOG_DIR/"
    echo ""
    echo "Uninstallation:"
    echo "=============="
    echo "Run:             sudo $INSTALL_DIR/uninstall.sh"
    echo ""
    print_warning "Important: Configure packet capture permissions for the agent user"
    print_warning "Run: sudo setcap cap_net_raw,cap_net_admin=eip $INSTALL_DIR/bin/cda_agent"
}

# Main installation function
main() {
    echo "=================================================="
    echo "  CDA (Cyber-defense Agent)"
    echo "                   Installer"
    echo "=================================================="
    echo ""

    check_root
    check_requirements
    create_directories
    build_project
    install_files
    create_config
    create_service
    create_scripts
    setup_logrotate
    create_uninstaller

    post_install_info
}

# Run main function
main "$@"
