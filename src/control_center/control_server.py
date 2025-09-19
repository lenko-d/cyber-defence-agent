#!/usr/bin/env python3
"""
CDA Remote Control Center
Provides a web interface for monitoring and controlling the CDA agent
"""

import json
import logging
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import requests
import threading
import time
from datetime import datetime
import os

class ControlCenter:
    def __init__(self, agent_host: str = "localhost", agent_port: int = 8080,
                 backend_host: str = "localhost", backend_port: int = 8080):
        self.agent_host = agent_host
        self.agent_port = agent_port
        self.backend_host = backend_host
        self.backend_port = backend_port

        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")

        self.setup_logging()
        self.setup_routes()
        self.setup_socket_events()

        # Agent status
        self.agent_status = "disconnected"
        self.last_update = None
        self.system_metrics = {}

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('control_center.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_routes(self):
        @self.app.route('/')
        def dashboard():
            return render_template('dashboard.html')

        @self.app.route('/api/status')
        def get_status():
            return jsonify({
                'agent_status': self.agent_status,
                'last_update': self.last_update,
                'system_metrics': self.system_metrics
            })

        @self.app.route('/api/command', methods=['POST'])
        def send_command():
            data = request.get_json()
            command = data.get('command')
            result = self.send_command_to_agent(command)
            return jsonify(result)

        @self.app.route('/api/logs')
        def get_logs():
            logs = self.get_agent_logs()
            return jsonify(logs)

    def setup_socket_events(self):
        @self.socketio.on('connect')
        def handle_connect():
            self.logger.info('Client connected')
            emit('status_update', {
                'agent_status': self.agent_status,
                'system_metrics': self.system_metrics
            })

        @self.socketio.on('disconnect')
        def handle_disconnect():
            self.logger.info('Client disconnected')

    def send_command_to_agent(self, command: str) -> dict:
        """Send command to the CDA agent"""
        try:
            url = f"http://{self.agent_host}:{self.agent_port}/command"
            response = requests.post(url, json={'command': command}, timeout=5)

            if response.status_code == 200:
                return {'success': True, 'result': response.json()}
            else:
                return {'success': False, 'error': f'HTTP {response.status_code}'}

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to send command to agent: {e}")
            return {'success': False, 'error': str(e)}

    def get_agent_logs(self) -> list:
        """Retrieve logs from the agent via HTTP"""
        try:
            url = f"http://{self.agent_host}:{self.agent_port}/logs"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                logs = response.json()
                return logs
            else:
                return [{'timestamp': datetime.now().isoformat(),
                        'message': f'Failed to get logs from agent: HTTP {response.status_code}'}]
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to get logs from agent: {e}")
            return [{'timestamp': datetime.now().isoformat(),
                    'message': f'Cannot connect to agent: {str(e)}'}]
        except Exception as e:
            self.logger.error(f"Failed to parse agent logs: {e}")
            return [{'timestamp': datetime.now().isoformat(),
                    'message': f'Error parsing logs: {e}'}]

    def update_system_metrics(self):
        """Update system metrics from agent"""
        try:
            url = f"http://{self.agent_host}:{self.agent_port}/status"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                self.system_metrics = data.get('metrics', {})
                self.agent_status = 'connected'
                self.last_update = datetime.now().isoformat()

                # Emit update to connected clients
                self.socketio.emit('status_update', {
                    'agent_status': self.agent_status,
                    'system_metrics': self.system_metrics,
                    'last_update': self.last_update
                })
            else:
                self.agent_status = 'error'

        except requests.exceptions.RequestException:
            self.agent_status = 'disconnected'

    def start_monitoring(self):
        """Start monitoring thread"""
        def monitor_loop():
            while True:
                self.update_system_metrics()
                time.sleep(5)  # Update every 5 seconds

        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()

    def run(self, host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
        """Start the control center"""
        self.logger.info(f"Starting CDA Control Center on {host}:{port}")

        # Start monitoring
        self.start_monitoring()

        # Start Flask app with production settings
        self.socketio.run(self.app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


# HTML Template for Dashboard
DASHBOARD_HTML = """
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
"""

# Create templates directory and dashboard template
def create_templates():
    os.makedirs('templates', exist_ok=True)
    with open('templates/dashboard.html', 'w') as f:
        f.write(DASHBOARD_HTML)

if __name__ == "__main__":
    # Create templates
    create_templates()

    # Start control center
    control_center = ControlCenter()
    control_center.run(debug=True)
