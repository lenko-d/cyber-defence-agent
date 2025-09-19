#!/bin/bash

# CDA LLM Backend Installer
# This script installs the CDA LLM Backend service

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/cda-llm-backend"
CONFIG_DIR="/etc/cda-llm-backend"
LOG_DIR="/var/log/cda-llm-backend"
SERVICE_NAME="aica-llm-backend"
PYTHON_VERSION="python3"

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

    # Check for Python
    if ! command -v "$PYTHON_VERSION" &> /dev/null; then
        print_error "Python 3 not found. Please install Python 3 first."
        exit 1
    fi

    # Check Python version
    PYTHON_MAJOR_VERSION=$($PYTHON_VERSION -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR_VERSION=$($PYTHON_VERSION -c 'import sys; print(sys.version_info.minor)')

    if [[ $PYTHON_MAJOR_VERSION -lt 3 ]] || [[ $PYTHON_MAJOR_VERSION -eq 3 && $PYTHON_MINOR_VERSION -lt 6 ]]; then
        print_error "Python 3.6 or higher is required."
        exit 1
    fi

    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found. Please install pip3 first."
        exit 1
    fi

    # Check for sudo
    if ! command -v sudo &> /dev/null; then
        print_error "sudo not found. Please install sudo first."
        exit 1
    fi

    print_success "System requirements check passed"
}

# Function to cleanup on failure
cleanup_on_failure() {
    print_warning "Installation failed. Cleaning up..."

    # Stop any running services
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true

    # Remove systemd service file
    sudo rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    sudo systemctl daemon-reload 2>/dev/null || true

    # Remove directories
    sudo rm -rf "$INSTALL_DIR"
    sudo rm -rf "$CONFIG_DIR"
    sudo rm -rf "$LOG_DIR"

    # Kill any remaining processes
    pkill -f "llm_backend.py" 2>/dev/null || true

    print_status "Cleanup completed"
}

# Function to create directories
create_directories() {
    print_status "Creating installation directories..."

    sudo mkdir -p "$INSTALL_DIR"
    sudo mkdir -p "$CONFIG_DIR"
    sudo mkdir -p "$LOG_DIR"

    # Set proper permissions
    sudo chown -R "$USER:$USER" "$INSTALL_DIR"
    sudo chown -R "$USER:$USER" "$CONFIG_DIR"
    sudo chown -R "$USER:$USER" "$LOG_DIR"

    print_success "Directories created successfully"
}

# Function to install Python dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."

    # Create virtual environment
    $PYTHON_VERSION -m venv "$INSTALL_DIR/venv"

    # Activate virtual environment and install dependencies
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install requests

    print_success "Python dependencies installed"
}

# Function to install LLM backend files
install_files() {
    print_status "Installing LLM backend files..."

    # Copy backend source
    cp -r src/backend/* "$INSTALL_DIR/"

    # Make the main script executable
    chmod +x "$INSTALL_DIR/llm_backend.py"

    print_success "LLM backend files installed"
}

# Function to create configuration files
create_config() {
    print_status "Creating configuration files..."

    # Create default configuration
    cat > "$CONFIG_DIR/llm_backend.conf" << EOF
# CDA LLM Backend Configuration File

[server]
host = localhost
port = 8081

[llm]
api_url = http://localhost:8000
api_key =

[logging]
log_level = INFO
log_file = $LOG_DIR/llm_backend.log
max_log_size = 100MB
max_log_files = 5

[knowledge_base]
knowledge_file = $INSTALL_DIR/knowledge_base.json
auto_save = true
EOF

    print_success "Configuration files created"
}

# Function to create systemd service
create_service() {
    print_status "Creating systemd service..."

    sudo tee "/etc/systemd/system/$SERVICE_NAME.service" > /dev/null << EOF
[Unit]
Description=CDA LLM Backend
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python llm_backend.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aica-llm-backend

# Environment
Environment=PATH=$INSTALL_DIR/venv/bin

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
# CDA LLM Backend Start Script

echo "Starting CDA LLM Backend..."
cd /opt/cda-llm-backend
source venv/bin/activate
python llm_backend.py &
echo $! > llm_backend.pid
echo "CDA LLM Backend started with PID $(cat llm_backend.pid)"
EOF

    # Create stop script
    cat > "$INSTALL_DIR/stop.sh" << 'EOF'
#!/bin/bash
# CDA LLM Backend Stop Script

if [[ -f "/opt/cda-llm-backend/llm_backend.pid" ]]; then
    PID=$(cat /opt/cda-llm-backend/llm_backend.pid)
    echo "Stopping CDA LLM Backend (PID: $PID)..."
    kill $PID
    rm -f /opt/cda-llm-backend/llm_backend.pid
    echo "CDA LLM Backend stopped"
else
    echo "CDA LLM Backend does not appear to be running"
fi
EOF

    # Create status script
    cat > "$INSTALL_DIR/status.sh" << 'EOF'
#!/bin/bash
# CDA LLM Backend Status Script

if [[ -f "/opt/cda-llm-backend/llm_backend.pid" ]]; then
    PID=$(cat /opt/cda-llm-backend/llm_backend.pid)
    if ps -p $PID > /dev/null; then
        echo "CDA LLM Backend is running (PID: $PID)"
        echo "Memory usage:"
        ps -p $PID -o pid,ppid,cmd,%mem,%cpu --no-headers
    else
        echo "CDA LLM Backend is not running (stale PID file)"
        rm -f /opt/cda-llm-backend/llm_backend.pid
    fi
else
    echo "CDA LLM Backend is not running"
fi

# Show recent log entries
echo ""
echo "Recent log entries:"
tail -n 10 /var/log/cda-llm-backend/llm_backend.log 2>/dev/null || echo "No log file found"
EOF

    # Make scripts executable
    chmod +x "$INSTALL_DIR/start.sh"
    chmod +x "$INSTALL_DIR/stop.sh"
    chmod +x "$INSTALL_DIR/status.sh"

    print_success "Utility scripts created"
}

# Function to create uninstaller
create_uninstaller() {
    print_status "Creating uninstaller..."

    cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
# CDA LLM Backend Uninstaller

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

echo "==============================================="
echo "  CDA LLM Backend Uninstaller"
echo "==============================================="
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
    exit 1
fi

print_status "Stopping CDA LLM Backend service..."
sudo systemctl stop aica-llm-backend 2>/dev/null || print_warning "Service was not running"
sudo systemctl disable aica-llm-backend 2>/dev/null || print_warning "Service was not enabled"

print_status "Removing systemd service..."
sudo rm -f /etc/systemd/system/aica-llm-backend.service
sudo systemctl daemon-reload

print_status "Removing files and directories..."
sudo rm -rf /opt/cda-llm-backend
sudo rm -rf /etc/cda-llm-backend
sudo rm -rf /var/log/cda-llm-backend

print_status "Checking for remaining processes..."
if pgrep -f "llm_backend.py" > /dev/null; then
    print_warning "Found remaining backend processes. Force killing..."
    pkill -f "llm_backend.py" || true
fi

print_status "Cleaning up user crontab entries..."
crontab -l 2>/dev/null | grep -v "aica-llm-backend" | crontab - 2>/dev/null || true

print_success "CDA LLM Backend has been completely removed!"
echo ""
echo "Removed components:"
echo "- Service files"
echo "- Installation directory (/opt/cda-llm-backend)"
echo "- Configuration directory (/etc/cda-llm-backend)"
echo "- Log directory (/var/log/cda-llm-backend)"
echo "- Any running processes"
echo "- Crontab entries"
EOF

    chmod +x "$INSTALL_DIR/uninstall.sh"

    print_success "Uninstaller created"
}

# Function to display post-installation information
post_install_info() {
    print_success "CDA LLM Backend installation completed successfully!"
    echo ""
    echo "Installation Summary:"
    echo "====================="
    echo "Install Directory: $INSTALL_DIR"
    echo "Config Directory: $CONFIG_DIR"
    echo "Log Directory: $LOG_DIR"
    echo ""
    echo "Service Management:"
    echo "=================="
    echo "Start service:   sudo systemctl start aica-llm-backend"
    echo "Stop service:    sudo systemctl stop aica-llm-backend"
    echo "Enable service:  sudo systemctl enable aica-llm-backend"
    echo "Check status:    sudo systemctl status aica-llm-backend"
    echo ""
    echo "Manual Control:"
    echo "=============="
    echo "Start manually:  $INSTALL_DIR/start.sh"
    echo "Stop manually:   $INSTALL_DIR/stop.sh"
    echo "Check status:    $INSTALL_DIR/status.sh"
    echo ""
    echo "Configuration:"
    echo "=============="
    echo "Config file:     $CONFIG_DIR/llm_backend.conf"
    echo "Log files:       $LOG_DIR/"
    echo ""
    echo "API Endpoints:"
    echo "=============="
    echo "Backend API:     http://localhost:8080"
    echo "LLM API:         http://localhost:8000 (configure in config file)"
    echo ""
    echo "Uninstallation:"
    echo "=============="
    echo "Run:             sudo $INSTALL_DIR/uninstall.sh"
    echo ""
    echo "Next Steps:"
    echo "==========="
    echo "1. Configure your LLM API endpoint in $CONFIG_DIR/llm_backend.conf"
    echo "2. Start the service: sudo systemctl start aica-llm-backend"
    echo "3. Check logs: tail -f $LOG_DIR/llm_backend.log"
}

# Main installation function
main() {
    echo "=================================================="
    echo "  CDA LLM Backend Installer"
    echo "=================================================="
    echo ""

    # Set up cleanup trap
    trap cleanup_on_failure ERR

    check_root
    check_requirements
    create_directories
    install_dependencies
    install_files
    create_config
    create_service
    create_scripts
    create_uninstaller

    post_install_info
}

# Run main function
main "$@"
