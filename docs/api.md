# API Reference

This document provides detailed API reference for CDA components.

## Agent Class

The main controller for the CDA system.

### Constructor
```cpp
CDA::Agent agent;
```

### Core Methods

#### `void initialize()`
Initializes the agent and all its components.

#### `void start()`
Starts the autonomous operation of the agent.

#### `void stop()`
Stops the agent's operation.

#### `void shutdown()`
Gracefully shuts down the agent and releases resources.

### Mission and Goals

#### `void setMission(const std::string& mission)`
Sets the primary mission for the agent.

#### `void addGoal(const std::string& goal)`
Adds a goal to the agent's objective list.

#### `void addConstraint(const std::string& constraint)`
Adds a constraint to limit the agent's actions.

### Autonomous Operation

#### `void assessSituation()`
Assesses the current security situation.

#### `void makeDecision()`
Makes autonomous decisions based on current situation.

#### `void executeAction()`
Executes the decided actions.

### Safety and Robustness

#### `void checkSafety()`
Performs safety checks on the system.

#### `void selfDefend()`
Initiates self-defense mechanisms.

#### `void recover()`
Attempts to recover from errors or attacks.

### Updates and Control

#### `void checkForUpdates()`
Checks for available updates.

#### `void receiveRemoteCommand(const std::string& command)`
Receives and processes remote commands.

#### `void restartAgent()`
Restarts the agent.

### LLM Integration

#### `bool analyzeWithLLM(const std::vector<std::string>& observations)`
Analyzes observations using LLM backend.

## PacketInspector Class

Handles real-time network packet inspection and threat detection.

### Constructor
```cpp
CDA::PacketInspector inspector;
```

### Methods

#### `bool startInspection(const std::string& interface = "")`
Starts packet inspection on the specified network interface.

#### `void stopInspection()`
Stops packet inspection.

#### `std::vector<PacketInfo> getRecentPackets()`
Returns recent packet information.

#### `std::vector<std::string> getSuspiciousPackets()`
Returns list of suspicious packet descriptions.

#### `void setPacketFilter(const std::string& filter)`
Sets a BPF filter for packet capture.

### PacketInfo Structure

```cpp
struct PacketInfo {
    std::string timestamp;
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    std::string protocol;
    uint32_t packet_size;
    std::string payload_sample;
    bool suspicious;
    std::string threat_type;
};
```

## UpdateManager Class

Manages secure updates and version control.

### Methods

#### `UpdateStatus checkForUpdates()`
Checks for available updates.

#### `void downloadUpdate(const std::string& version)`
Downloads the specified update version.

#### `void installUpdate(const std::string& version)`
Installs the downloaded update.

## Component Interfaces

### Monitor Interface

```cpp
class Monitor {
public:
    virtual void startMonitoring() = 0;
    virtual void stopMonitoring() = 0;
    virtual std::vector<std::string> getObservations() = 0;
    virtual double getCpuUsage() = 0;
    virtual double getMemoryUsage() = 0;
};
```

### Detector Interface

```cpp
class Detector {
public:
    virtual bool detectMalware(const std::vector<std::string>& observations) = 0;
    virtual std::string classifyThreat(const std::string& observation) = 0;
};
```

### Responder Interface

```cpp
class Responder {
public:
    virtual void respondToThreat(const std::string& threat) = 0;
    virtual void quarantineMalware(const std::string& malware) = 0;
    virtual void alertOperator(const std::string& alert) = 0;
};
```

## Factory Functions

### `std::unique_ptr<Monitor> createMonitor()`
Creates a new Monitor instance.

### `std::unique_ptr<Detector> createDetector()`
Creates a new Detector instance.

## HTTP API

CDA provides an HTTP interface for remote monitoring and control.

### Endpoints

- `GET /status` - Returns agent status
- `POST /command` - Executes remote commands
- `GET /logs` - Retrieves recent logs

### Example Usage

```bash
curl http://localhost:8080/status
curl -X POST http://localhost:8080/command -d "restart"
