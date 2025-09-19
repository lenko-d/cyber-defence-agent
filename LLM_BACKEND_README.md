# CDA LLM Backend Installer

This installer sets up the CDA LLM Backend service, which provides advanced AI-powered analysis and decision support for the CDA cybersecurity agent.

## Features

- **Threat Analysis**: Uses Large Language Models to analyze system observations for potential threats
- **Response Planning**: Generates comprehensive response plans for detected threats
- **Predictive Analysis**: Predicts future threats based on historical data
- **Knowledge Base**: Learns from previous analyses to improve future detection
- **REST API**: Provides HTTP endpoints for integration with other CDA components

## Installation

### Prerequisites

- Python 3.6 or higher
- pip3 package manager
- sudo privileges (for system service installation)
- Linux system with systemd

### Quick Install

```bash
# Make the installer executable
chmod +x llm_backend_install.sh

# Run the installer (requires sudo for system integration)
./llm_backend_install.sh
```

## Configuration

After installation, configure the LLM backend by editing `/etc/cda-llm-backend/llm_backend.conf`:

```ini
[server]
host = localhost
port = 8081

[llm]
api_url = http://localhost:8000
api_key = your_llm_api_key_here

[logging]
log_level = INFO
log_file = /var/log/cda-llm-backend/llm_backend.log
max_log_size = 100MB
max_log_files = 5

[knowledge_base]
knowledge_file = /opt/cda-llm-backend/knowledge_base.json
auto_save = true
```

### LLM API Configuration

The backend supports various LLM APIs. Configure the `api_url` and `api_key` in the configuration file:

- **OpenAI**: `https://api.openai.com/v1/chat/completions`
- **Local LLM**: `http://localhost:8000/generate` (for local models)
- **Other APIs**: Any API that accepts JSON POST requests

## Usage

### Service Management

```bash
# Start the service
sudo systemctl start aica-llm-backend

# Stop the service
sudo systemctl stop aica-llm-backend

# Enable auto-start on boot
sudo systemctl enable aica-llm-backend

# Check service status
sudo systemctl status aica-llm-backend
```

### Manual Control

```bash
# Start manually
/opt/cda-llm-backend/start.sh

# Stop manually
/opt/cda-llm-backend/stop.sh

# Check status
/opt/cda-llm-backend/status.sh
```

### API Endpoints

The backend provides the following REST API endpoints:

#### Threat Analysis
```bash
POST http://localhost:8081/analyze_threat
Content-Type: application/json

{
  "action": "analyze_threat",
  "observations": [
    "Suspicious process detected: /usr/bin/nc",
    "Network connection to unusual port: 4444"
  ]
}
```

#### Response Planning
```bash
POST http://localhost:8081/generate_response
Content-Type: application/json

{
  "action": "generate_response",
  "threat_analysis": {
    "threat_level": "high",
    "threats": ["Unauthorized network connection"],
    "confidence": 0.95
  }
}
```

#### Threat Prediction
```bash
POST http://localhost:8081/predict_threats
Content-Type: application/json

{
  "action": "predict_threats",
  "historical_data": [
    {
      "timestamp": "2025-01-01T10:00:00",
      "threat_level": "medium",
      "description": "Suspicious login attempt"
    }
  ]
}
```

## File Structure

After installation, the following directories and files are created:

```
/opt/cda-llm-backend/
├── llm_backend.py          # Main backend script
├── venv/                   # Python virtual environment
├── knowledge_base.json     # Learned threat patterns
├── start.sh               # Manual start script
├── stop.sh                # Manual stop script
├── status.sh              # Status check script
└── uninstall.sh           # Uninstaller script

/etc/cda-llm-backend/
└── llm_backend.conf       # Configuration file

/var/log/cda-llm-backend/
└── llm_backend.log        # Log files

/etc/systemd/system/
└── aica-llm-backend.service # Systemd service file
```

## Logging

The backend logs all activities to `/var/log/cda-llm-backend/llm_backend.log`. Monitor logs with:

```bash
tail -f /var/log/cda-llm-backend/llm_backend.log
```

## Troubleshooting

### Common Issues

1. **LLM API Connection Failed**
   - Check the `api_url` in the configuration file
   - Verify the API key is correct
   - Ensure the LLM service is running and accessible

2. **Service Won't Start**
   - Check system logs: `journalctl -u aica-llm-backend`
   - Verify Python dependencies: `source /opt/cda-llm-backend/venv/bin/activate && python -c "import requests"`

3. **Permission Errors**
   - Ensure the user has sudo privileges for installation
   - Check file permissions in the installation directory

### Log Analysis

```bash
# View recent errors
grep "ERROR" /var/log/cda-llm-backend/llm_backend.log

# Monitor API requests
grep "POST" /var/log/cda-llm-backend/llm_backend.log
```

## Integration with CDA Agent

The LLM backend is designed to work with the main CDA agent. Configure the agent to connect to the backend API at `http://localhost:8081` for enhanced threat analysis and response planning.

## Uninstallation

To completely remove the LLM backend:

```bash
sudo /opt/cda-llm-backend/uninstall.sh
```

This will:
- Stop and disable the service
- Remove all installed files and directories
- Clean up systemd configuration
- Kill any remaining processes

## Security Considerations

- Store API keys securely and avoid hardcoding them
- Use HTTPS for API communications in production
- Regularly update the LLM backend and dependencies
- Monitor logs for unusual activity
- Restrict access to the backend API endpoints

## Support

For issues or questions:
1. Check the logs in `/var/log/cda-llm-backend/`
2. Verify configuration in `/etc/cda-llm-backend/llm_backend.conf`
3. Ensure the LLM API service is accessible
4. Review the troubleshooting section above

## License

This installer and the CDA LLM Backend are part of the CDA (Cyber-defense Agent) project.
