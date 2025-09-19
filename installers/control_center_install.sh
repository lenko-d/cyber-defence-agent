#!/bin/bash

# CDA Control Center Installer
# This script installs the CDA Control Center web interface

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/aica-control-center"
CONFIG_DIR="/etc/aica-control-center"
LOG_DIR="/var/log/aica-control-center"
SERVICE_NAME="aica-control-center"
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
    pkill -f "control_server.py" 2>/dev/null || true

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
    pip install flask flask-socketio requests python-socketio

    print_success "Python dependencies installed"
}

# Function to install control center files
install_files() {
    print_status "Installing control center files..."

    # Copy control center source
    cp -r src/control_center/* "$INSTALL_DIR/"

    # Create templates directory
    mkdir -p "$INSTALL_DIR/templates"

    # Create the dashboard template
    cat > "$INSTALL_DIR/templates/dashboard.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CDA Control Center</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .status-panel { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .metric-card { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }
        .metric-value { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .metric-label { color: #6c757d; margin-top: 5px; }
        .command-panel { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .logs-panel { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .status-connected { background-color: #28a745; }
        .status-disconnected { background-color: #dc3545; }
        .status-error { background-color: #ffc107; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        input[type="text"] { padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 4px; width: 300px; }
        .log-entry { padding: 5px 0; border-bottom: 1px solid #eee; font-family: monospace; font-size: 12px; }
        .log-timestamp { color: #6c757d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CDA Control Center</h1>
            <p>Cyber-defense Agent</p>
        </div>

        <div class="status-panel">
            <h2>Agent Status</h2>
            <div id="agent-status">
                <span class="status-indicator status-disconnected"></span>
                <span id="status-text">Connecting...</span>
            </div>
            <div id="last-update">Last update: Never</div>
        </div>

        <div class="metrics-grid" id="metrics-grid">
            <!-- Metrics will be populated by JavaScript -->
        </div>

        <div class="command-panel">
            <h2>Send Command</h2>
            <input type="text" id="command-input" placeholder="Enter command...">
            <button onclick="sendCommand()">Send</button>
            <div id="command-result"></div>
        </div>

        <div class="logs-panel">
            <h2>Agent Logs</h2>
            <div id="logs-container">
                <!-- Logs will be populated by JavaScript -->
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        const statusIndicator = document.querySelector('.status-indicator');
        const statusText = document.getElementById('status-text');
        const lastUpdate = document.getElementById('last-update');
        const metricsGrid = document.getElementById('metrics-grid');
        const logsContainer = document.getElementById('logs-container');

        socket.on('status_update', function(data) {
            updateStatus(data.agent_status);
            updateMetrics(data.system_metrics);
            lastUpdate.textContent = 'Last update: ' + (data.last_update || 'Never');
        });

        function updateStatus(status) {
            statusText.textContent = status.charAt(0).toUpperCase() + status.slice(1);

            statusIndicator.className = 'status-indicator';
            if (status === 'connected') {
                statusIndicator.classList.add('status-connected');
            } else if (status === 'disconnected') {
                statusIndicator.classList.add('status-disconnected');
            } else {
                statusIndicator.classList.add('status-error');
            }
        }

        function updateMetrics(metrics) {
            metricsGrid.innerHTML = '';

            if (Object.keys(metrics).length === 0) {
                metricsGrid.innerHTML = '<div class="metric-card"><div class="metric-value">-</div><div class="metric-label">No metrics available</div></div>';
                return;
            }

            for (const [key, value] of Object.entries(metrics)) {
                const card = document.createElement('div');
                card.className = 'metric-card';
                card.innerHTML = `
                    <div class="metric-value">${value}</div>
                    <div class="metric-label">${key.replace(/_/g, ' ')}</div>
                `;
                metricsGrid.appendChild(card);
            }
        }

        function sendCommand() {
            const command = document.getElementById('command-input').value;
            if (!command.trim()) return;

            fetch('/api/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: command })
            })
            .then(response => response.json())
            .then(data => {
                const resultDiv = document.getElementById('command-result');
                if (data.success) {
                    resultDiv.innerHTML = '<span style="color: green;">Command sent successfully</span>';
                } else {
                    resultDiv.innerHTML = '<span style="color: red;">Error: ' + data.error + '</span>';
                }
                document.getElementById('command-input').value = '';
            })
            .catch(error => {
                document.getElementById('command-result').innerHTML = '<span style="color: red;">Network error</span>';
            });
        }

        function loadLogs() {
            fetch('/api/logs')
            .then(response => response.json())
            .then(logs => {
                logsContainer.innerHTML = '';
                logs.forEach(log => {
                    const logEntry = document.createElement('div');
                    logEntry.className = 'log-entry';
                    logEntry.innerHTML = `
                        <span class="log-timestamp">${log.timestamp}</span>
                        <span>${log.message}</span>
                    `;
                    logsContainer.appendChild(logEntry);
                });
            })
            .catch(error => {
                logsContainer.innerHTML = '<div class="log-entry">Error loading logs</div>';
            });
        }

        // Load initial data
        loadLogs();
        setInterval(loadLogs, 10000); // Refresh logs every 10 seconds

        // Allow sending command with Enter key
        document.getElementById('command-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendCommand();
            }
        });
    </script>
</body>
</html>
EOF

    print_success "Control center files installed"
}

# Function to create configuration files
create_config() {
    print_status "Creating configuration files..."

    # Create default configuration
    cat > "$CONFIG_DIR/control_center.conf" << EOF
# CDA Control Center Configuration File

[server]
host = 0.0.0.0
port = 5000
debug = false

[agent]
host = localhost
port = 8080

[backend]
host = localhost
port = 8080

[logging]
log_level = INFO
log_file = $LOG_DIR/control_center.log
max_log_size = 100MB
max_log_files = 5
EOF

    print_success "Configuration files created"
}

# Function to create systemd service
create_service() {
    print_status "Creating systemd service..."

    sudo tee "/etc/systemd/system/$SERVICE_NAME.service" > /dev/null << EOF
[Unit]
Description=CDA Control Center
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python control_server.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aica-control-center

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
# CDA Control Center Start Script

echo "Starting CDA Control Center..."
cd /opt/aica-control-center
source venv/bin/activate
python control_server.py &
echo $! > control_center.pid
echo "CDA Control Center started with PID $(cat control_center.pid)"
EOF

    # Create stop script
    cat > "$INSTALL_DIR/stop.sh" << 'EOF'
#!/bin/bash
# CDA Control Center Stop Script

if [[ -f "/opt/aica-control-center/control_center.pid" ]]; then
    PID=$(cat /opt/aica-control-center/control_center.pid)
    echo "Stopping CDA Control Center (PID: $PID)..."
    kill $PID
    rm -f /opt/aica-control-center/control_center.pid
    echo "CDA Control Center stopped"
else
    echo "CDA Control Center does not appear to be running"
fi
EOF

    # Create status script
    cat > "$INSTALL_DIR/status.sh" << 'EOF'
#!/bin/bash
# CDA Control Center Status Script

if [[ -f "/opt/aica-control-center/control_center.pid" ]]; then
    PID=$(cat /opt/aica-control-center/control_center.pid)
    if ps -p $PID > /dev/null; then
        echo "CDA Control Center is running (PID: $PID)"
        echo "Memory usage:"
        ps -p $PID -o pid,ppid,cmd,%mem,%cpu --no-headers
    else
        echo "CDA Control Center is not running (stale PID file)"
        rm -f /opt/aica-control-center/control_center.pid
    fi
else
    echo "CDA Control Center is not running"
fi

# Show recent log entries
echo ""
echo "Recent log entries:"
tail -n 10 /var/log/aica-control-center/control_center.log 2>/dev/null || echo "No log file found"
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
# CDA Control Center Uninstaller

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
echo "  CDA Control Center Uninstaller"
echo "==============================================="
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
    exit 1
fi

print_status "Stopping CDA Control Center service..."
sudo systemctl stop aica-control-center 2>/dev/null || print_warning "Service was not running"
sudo systemctl disable aica-control-center 2>/dev/null || print_warning "Service was not enabled"

print_status "Removing systemd service..."
sudo rm -f /etc/systemd/system/aica-control-center.service
sudo systemctl daemon-reload

print_status "Removing files and directories..."
sudo rm -rf /opt/aica-control-center
sudo rm -rf /etc/aica-control-center
sudo rm -rf /var/log/aica-control-center

print_status "Checking for remaining processes..."
if pgrep -f "control_server.py" > /dev/null; then
    print_warning "Found remaining control center processes. Force killing..."
    pkill -f "control_server.py" || true
fi

print_status "Cleaning up user crontab entries..."
crontab -l 2>/dev/null | grep -v "aica-control-center" | crontab - 2>/dev/null || true

print_success "CDA Control Center has been completely removed!"
echo ""
echo "Removed components:"
echo "- Service files"
echo "- Installation directory (/opt/aica-control-center)"
echo "- Configuration directory (/etc/aica-control-center)"
echo "- Log directory (/var/log/aica-control-center)"
echo "- Any running processes"
echo "- Crontab entries"
EOF

    chmod +x "$INSTALL_DIR/uninstall.sh"

    print_success "Uninstaller created"
}

# Function to display post-installation information
post_install_info() {
    print_success "CDA Control Center installation completed successfully!"
    echo ""
    echo "Installation Summary:"
    echo "====================="
    echo "Install Directory: $INSTALL_DIR"
    echo "Config Directory: $CONFIG_DIR"
    echo "Log Directory: $LOG_DIR"
    echo ""
    echo "Service Management:"
    echo "=================="
    echo "Start service:   sudo systemctl start aica-control-center"
    echo "Stop service:    sudo systemctl stop aica-control-center"
    echo "Enable service:  sudo systemctl enable aica-control-center"
    echo "Check status:    sudo systemctl status aica-control-center"
    echo ""
    echo "Manual Control:"
    echo "=============="
    echo "Start manually:  $INSTALL_DIR/start.sh"
    echo "Stop manually:   $INSTALL_DIR/stop.sh"
    echo "Check status:    $INSTALL_DIR/status.sh"
    echo ""
    echo "Configuration:"
    echo "=============="
    echo "Config file:     $CONFIG_DIR/control_center.conf"
    echo "Log files:       $LOG_DIR/"
    echo ""
    echo "Web Interface:"
    echo "=============="
    echo "Access the control center at: http://localhost:5000"
    echo ""
    echo "Uninstallation:"
    echo "=============="
    echo "Run:             sudo $INSTALL_DIR/uninstall.sh"
}

# Main installation function
main() {
    echo "=================================================="
    echo "  CDA Control Center Installer"
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
