# Developer Guide

This guide is for developers who want to contribute to CDA or extend its functionality.

## Development Environment Setup

### Prerequisites

- Linux development environment
- CMake 3.16+
- C++17 compiler (GCC 7+ or Clang 5+)
- Python 3.8+ for backend components
- Git for version control
- IDE with C++ support (VSCode, CLion, etc.)

### Cloning and Building

```bash
# Clone with submodules if any
git clone --recursive https://github.com/your-repo/aica-agent.git
cd aica-agent

# Create build directory
mkdir build && cd build

# Configure build
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Build
make -j$(nproc)

# Run tests
make test
```

### Development Dependencies

```bash
# Install development tools
sudo apt install build-essential cmake gdb valgrind clang-format

# Install testing frameworks
sudo apt install googletest libgtest-dev

# Python development
pip install pytest black mypy
```

## Project Structure

```
aica-agent/
├── src/
│   ├── agent/           # Core agent components
│   │   ├── Agent.cpp    # Main agent implementation
│   │   ├── Monitor.cpp  # System monitoring
│   │   ├── Detector.cpp # Threat detection
│   │   └── PacketInspector.cpp # Network inspection
│   ├── backend/         # Python backend services
│   └── control_center/  # Control interface
├── include/             # Public headers
├── tests/               # Unit and integration tests
├── docs/                # Documentation
├── build/               # Build artifacts
└── CMakeLists.txt       # Build configuration
```

## Architecture Overview

### Core Components

#### Agent
The central coordinator that manages all other components.

#### Monitor
Responsible for system observation and metrics collection.

#### Detector
Implements threat detection algorithms and pattern matching.

#### PacketInspector
Handles network packet capture and analysis using libpcap.

#### UpdateManager
Manages secure software updates and version control.

#### Responder
Executes automated responses to detected threats.

### Design Patterns

CDA uses several design patterns:

- **Observer Pattern**: For event-driven threat detection
- **Strategy Pattern**: For pluggable detection algorithms
- **Factory Pattern**: For component instantiation
- **Command Pattern**: For remote control and undo operations

## Contributing

### Code Style

#### C++ Guidelines

- Use C++17 features
- Follow Google C++ Style Guide
- Use smart pointers for memory management
- Prefer const correctness
- Use RAII principles

#### Python Guidelines

- Follow PEP 8
- Use type hints
- Write docstrings for all public functions
- Use virtual environments

### Code Formatting

```bash
# Format C++ code
find src include -name "*.cpp" -o -name "*.h" | xargs clang-format -i

# Format Python code
black src/backend/
```

### Testing

#### Unit Tests

```cpp
// Example unit test using Google Test
TEST(PacketInspectorTest, DetectsMaliciousPayload) {
    PacketInspector inspector;
    std::vector<uint8_t> malicious_payload = {0x90, 0x90, 0x90}; // NOP sled
    EXPECT_TRUE(inspector.detectMaliciousPatterns(malicious_payload.data(), malicious_payload.size()));
}
```

#### Integration Tests

```bash
# Run all tests
make test

# Run specific test suite
./tests/integration_tests --gtest_filter=PacketInspectorTest.*
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation
7. Submit pull request

## Extending CDA

### Adding New Detection Rules

```cpp
class CustomDetector : public CDA::Detector {
public:
    bool detectMalware(const std::vector<std::string>& observations) override {
        // Implement custom detection logic
        for (const auto& obs : observations) {
            if (obs.find("suspicious_pattern") != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    std::string classifyThreat(const std::string& observation) override {
        return "CUSTOM_THREAT";
    }
};
```

### Creating New Components

1. Define interface in `include/CDA.h`
2. Implement concrete class
3. Register with factory functions
4. Add to Agent initialization

### Plugin System

CDA supports runtime plugins for extensibility:

```cpp
// Plugin interface
class Plugin {
public:
    virtual std::string getName() = 0;
    virtual void initialize() = 0;
    virtual void process(const std::string& data) = 0;
};

// Load plugin dynamically
std::unique_ptr<Plugin> loadPlugin(const std::string& path);
```

## Performance Optimization

### Profiling

```bash
# Use perf for CPU profiling
perf record ./aica_agent
perf report

# Memory profiling with Valgrind
valgrind --tool=massif ./aica_agent

# Heap profiling
valgrind --tool=memcheck --leak-check=full ./aica_agent
```

### Optimization Techniques

- Use asynchronous I/O for network operations
- Implement connection pooling
- Cache frequently accessed data
- Use lock-free data structures where possible
- Profile and optimize hot paths

## Security Considerations

### Secure Coding Practices

- Validate all inputs
- Use secure random number generation
- Implement proper error handling
- Avoid buffer overflows
- Use secure communication protocols

### Code Review Checklist

- [ ] Input validation
- [ ] Error handling
- [ ] Memory management
- [ ] Thread safety
- [ ] Security implications
- [ ] Performance impact
- [ ] Documentation updates

## Debugging

### Debug Build

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make

# Run with debugger
gdb ./aica_agent
```

### Logging

CDA uses a configurable logging system:

```cpp
#include "Logger.h"

Logger::getInstance().log(LogLevel::INFO, "Agent started");
Logger::getInstance().log(LogLevel::ERROR, "Failed to initialize detector");
```

### Common Debug Scenarios

- Packet capture issues
- Memory leaks
- Thread deadlocks
- Performance bottlenecks

## Deployment

### Containerization

```dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY build/aica_agent /usr/local/bin/
COPY config/aica_config.txt /etc/aica/

CMD ["aica_agent", "--config", "/etc/aica/aica_config.txt"]
```

### CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Build
      run: |
        mkdir build && cd build
        cmake ..
        make -j$(nproc)
    - name: Test
      run: make test
```

## Resources

- [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
- [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [CMake Documentation](https://cmake.org/documentation/)
