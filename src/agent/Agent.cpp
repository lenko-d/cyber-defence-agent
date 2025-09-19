#include "CDA.h"
#include "PacketInspector.h"
#include "UpdateManager.h"
#include <iostream>
#include <chrono>
#include <fstream>
#include <unistd.h>
#include <cstring>
#include <climits>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

namespace CDA {

Agent::Agent() : running_(false), threats_detected_(0), httpServerThread_(nullptr), serverSocket_(-1) {
    // Initialize components
    monitor_ = createMonitor();
    detector_ = createDetector();
    packetInspector_ = std::make_unique<PacketInspector>();
    updateManager_ = std::make_unique<UpdateManager>();
    // Other components will be implemented later
}

Agent::~Agent() {
    stop();
}

void Agent::initialize() {
    std::cout << "Initializing CDA Agent..." << std::endl;

    // Set default mission
    mission_ = "Protect the system from malware threats through autonomous monitoring, detection, and response";

    // Add default goals
    goals_.push_back("Monitor system activity continuously");
    goals_.push_back("Detect and classify malware threats");
    goals_.push_back("Respond to threats autonomously");
    goals_.push_back("Maintain system safety and integrity");

    // Add default constraints
    constraints_.push_back("Minimize false positives");
    constraints_.push_back("Avoid harming legitimate processes");
    constraints_.push_back("Maintain system performance");

    logEvent("Agent initialized with mission: " + mission_);
}

void Agent::start() {
    if (running_) return;

    running_ = true;
    std::cout << "Starting CDA Agent..." << std::endl;

    // Start packet inspection
    if (packetInspector_) {
        packetInspector_->startInspection();
    }

    // Start monitoring thread
    monitorThread_ = std::thread(&Agent::monitorLoop, this);

    // Start decision thread
    decisionThread_ = std::thread(&Agent::decisionLoop, this);

    // Start execution thread
    executionThread_ = std::thread(&Agent::executionLoop, this);

    // Start HTTP server for control center communication
    httpServerThread_ = std::make_unique<std::thread>(&Agent::startHttpServer, this);

    logEvent("Agent started successfully");
}

void Agent::stop() {
    if (!running_) return;

    running_ = false;
    std::cout << "Stopping CDA Agent..." << std::endl;

    // Close HTTP server socket to unblock accept()
    if (serverSocket_ >= 0) {
        close(serverSocket_);
        serverSocket_ = -1;
    }

    // Join threads
    if (monitorThread_.joinable()) monitorThread_.join();
    if (decisionThread_.joinable()) decisionThread_.join();
    if (executionThread_.joinable()) executionThread_.join();
    if (httpServerThread_ && httpServerThread_->joinable()) {
        httpServerThread_->join();
    }

    logEvent("Agent stopped");
}

void Agent::shutdown() {
    stop();
    logEvent("Agent shutdown complete");
}

void Agent::setMission(const std::string& mission) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    mission_ = mission;
    logEvent("Mission updated: " + mission);
}

void Agent::addGoal(const std::string& goal) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    goals_.push_back(goal);
    logEvent("Goal added: " + goal);
}

void Agent::addConstraint(const std::string& constraint) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    constraints_.push_back(constraint);
    logEvent("Constraint added: " + constraint);
}

void Agent::assessSituation() {
    // Assess current system situation
    std::vector<std::string> all_observations;

    if (monitor_) {
        auto observations = monitor_->getObservations();
        all_observations.insert(all_observations.end(), observations.begin(), observations.end());
    }

    // Add packet inspection data
    if (packetInspector_) {
        auto suspicious_packets = packetInspector_->getSuspiciousPackets();
        for (const auto& packet : suspicious_packets) {
            all_observations.push_back("Packet: " + packet);
        }

        auto recent_packets = packetInspector_->getRecentPackets();
        if (!recent_packets.empty()) {
            all_observations.push_back("Packets: " + std::to_string(recent_packets.size()) + " packets inspected");
        }
    }

    std::cout << "Monitoring observations:" << std::endl;
    for (const auto& obs : all_observations) {
        std::cout << "  " << obs << std::endl;
    }

    std::string assessment_outcome = "Assessment completed: " + std::to_string(all_observations.size()) + " observations analyzed";

    bool basicThreatDetected = detector_ && detector_->detectMalware(all_observations);
    bool llmThreatDetected = analyzeWithLLM(all_observations);

    if (basicThreatDetected || llmThreatDetected) {
        std::cout << "THREAT DETECTED!" << std::endl;
        threats_detected_++;  // Increment threat counter
        assessment_outcome += " | THREAT DETECTED - " + std::to_string(threats_detected_.load()) + " total threats";

        if (basicThreatDetected) {
            assessment_outcome += " (Basic detection)";
        }
        if (llmThreatDetected) {
            assessment_outcome += " (LLM analysis)";
        }

        // Log detailed threat information
        std::string threat_details = "Malware threat detected";
        for (const auto& obs : all_observations) {
            if (obs.find("Packet:") != std::string::npos ||
                obs.find("SUSPICIOUS:") != std::string::npos ||
                obs.find("unusual") != std::string::npos ||
                obs.find("anomalous") != std::string::npos) {
                threat_details += " | " + obs;
            }
        }
        logEvent(threat_details);
    } else {
        assessment_outcome += " | No threats detected";
    }

    std::cout << "Assessment outcome: " << assessment_outcome << std::endl;
    logEvent(assessment_outcome);
}

void Agent::makeDecision() {
    // Make autonomous decisions based on current situation
    // This would involve analyzing observations and planning responses
    std::cout << "Making decision..." << std::endl;

    // Analyze current situation and make a decision
    std::string decision = "Continue monitoring - no immediate action required";

    if (threats_detected_.load() > 0) {
        decision = "Threat detected - initiating defensive measures";
    }

    std::cout << "Decision: " << decision << std::endl;
    logEvent("Decision made: " + decision);
}

void Agent::executeAction() {
    // Execute planned actions
    // This would involve carrying out the decided response
    std::cout << "Executing action..." << std::endl;
    logEvent("Action executed");
}

void Agent::checkSafety() {
    // Check if actions are safe to execute
    std::cout << "Checking safety..." << std::endl;

    // Perform safety checks
    std::string safety_status = "Safety check completed";

    // Check system resources
    if (monitor_) {
        double cpu_usage = monitor_->getCpuUsage();
        double memory_usage = monitor_->getMemoryUsage();

        if (cpu_usage > 90.0) {
            safety_status += " | WARNING: High CPU usage (" + std::to_string(static_cast<int>(cpu_usage)) + "%)";
        }
        if (memory_usage > 90.0) {
            safety_status += " | WARNING: High memory usage (" + std::to_string(static_cast<int>(memory_usage)) + "%)";
        }
    }

    // Check threat levels
    int current_threats = threats_detected_.load();
    if (current_threats > 10) {
        safety_status += " | WARNING: High threat count (" + std::to_string(current_threats) + ")";
    }

    // Check if all systems are operational
    bool systems_ok = true;
    if (!monitor_) {
        safety_status += " | ERROR: Monitor system unavailable";
        systems_ok = false;
    }
    if (!detector_) {
        safety_status += " | ERROR: Detector system unavailable";
        systems_ok = false;
    }

    if (systems_ok && current_threats <= 10) {
        safety_status += " | All systems operational";
    }

    std::cout << "Safety status: " << safety_status << std::endl;
    logEvent(safety_status);
}

void Agent::selfDefend() {
    // Defend against attacks on the agent itself
    std::cout << "Self-defense activated..." << std::endl;
    logEvent("Self-defense measures taken");
}

void Agent::recover() {
    // Recover from degraded state
    std::cout << "Recovery initiated..." << std::endl;
    logEvent("Recovery completed");
}

void Agent::checkForUpdates() {
    // Check for agent updates using UpdateManager
    if (updateManager_) {
        std::cout << "Checking for updates..." << std::endl;

        UpdateStatus status = updateManager_->checkForUpdates();

        if (status.update_available) {
            std::cout << "Update available: " << status.latest_version.version << std::endl;
            std::cout << "Changelog: " << status.latest_version.changelog << std::endl;

            // Optionally auto-install if enabled
            if (updateManager_->isUpdateAvailable()) {
                std::cout << "Downloading update..." << std::endl;
                if (updateManager_->downloadUpdate(status.latest_version)) {
                    std::cout << "Installing update..." << std::endl;
                    if (updateManager_->installUpdate(status.latest_version)) {
                        std::cout << "Update installed successfully. Restarting agent..." << std::endl;
                        logEvent("Update installed successfully, initiating restart");

                        // Stop current operations
                        stop();

                        // Schedule restart with a delay to allow cleanup
                        std::thread([this]() {
                            std::this_thread::sleep_for(std::chrono::seconds(3));
                            restartAgent();
                        }).detach();

                        return; // Exit early as we're restarting
                    } else {
                        std::cout << "Update installation failed: " << updateManager_->getLastError() << std::endl;
                        logEvent("Update installation failed: " + updateManager_->getLastError());
                    }
                } else {
                    std::cout << "Update download failed: " << updateManager_->getLastError() << std::endl;
                    logEvent("Update download failed: " + updateManager_->getLastError());
                }
            }
        } else {
            std::cout << "Agent is up to date" << std::endl;
        }

        logEvent("Update check completed: " + status.status_message);
    } else {
        std::cout << "Update manager not available" << std::endl;
        logEvent("Update check failed: Update manager not available");
    }
}

void Agent::receiveRemoteCommand(const std::string& command) {
    // Process remote commands from control center
    std::cout << "Received remote command: " << command << std::endl;
    logEvent("Remote command processed: " + command);
}

void Agent::monitorLoop() {
    while (running_) {
        assessSituation();
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Monitor every 5 seconds
    }
}

void Agent::decisionLoop() {
    while (running_) {
        makeDecision();
        std::this_thread::sleep_for(std::chrono::seconds(10)); // Decide every 10 seconds
    }
}

void Agent::executionLoop() {
    int update_check_counter = 0;
    while (running_) {
        checkSafety();
        executeAction();

        // Check for updates every 4 iterations (every 60 seconds)
        update_check_counter++;
        if (update_check_counter >= 4) {
            checkForUpdates();
            update_check_counter = 0;
        }

        std::this_thread::sleep_for(std::chrono::seconds(15)); // Execute every 15 seconds
    }
}

void Agent::restartAgent() {
    std::cout << "Restarting CDA Agent..." << std::endl;
    logEvent("Agent restart initiated");

    // Get the current executable path
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        std::cerr << "Failed to get executable path for restart" << std::endl;
        logEvent("Agent restart failed: Could not get executable path");
        return;
    }
    exe_path[len] = '\0';

    // Prepare arguments for exec
    char* const argv[] = {exe_path, nullptr};

    // Execute the new process
    logEvent("Agent restarting with new binary");
    execv(exe_path, argv);

    // If we reach here, exec failed
    std::cerr << "Failed to restart agent: " << strerror(errno) << std::endl;
    logEvent("Agent restart failed: " + std::string(strerror(errno)));
}

void Agent::startHttpServer() {
    int port = 8080;
    struct sockaddr_in server_addr;

    // Create socket
    serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket_ < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return;
    }

    // Set socket options
    int opt = 1;
    setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind socket
    if (bind(serverSocket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        close(serverSocket_);
        return;
    }

    // Listen for connections
    if (listen(serverSocket_, 5) < 0) {
        std::cerr << "Failed to listen on socket" << std::endl;
        close(serverSocket_);
        return;
    }

    std::cout << "HTTP server started on port " << port << std::endl;
    logEvent("HTTP server started on port " + std::to_string(port));

    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(serverSocket_, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket < 0) {
            if (running_) {
                std::cerr << "Failed to accept connection" << std::endl;
            }
            continue;
        }

        // Handle request in a separate thread
        std::thread(&Agent::handleHttpRequest, this, client_socket).detach();
    }

    close(serverSocket_);
    serverSocket_ = -1;
}

void Agent::handleHttpRequest(int client_socket) {
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    // Read request
    ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        close(client_socket);
        return;
    }

    std::string request(buffer);
    std::string response;

    // Parse request
    if (request.find("GET /status") != std::string::npos) {
        response = handleStatusRequest();
    } else if (request.find("POST /command") != std::string::npos) {
        response = handleCommandRequest(request);
    } else if (request.find("GET /logs") != std::string::npos) {
        response = handleLogsRequest();
    } else {
        response = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n{\"error\": \"Endpoint not found\"}";
    }

    // Send response
    write(client_socket, response.c_str(), response.length());
    close(client_socket);
}

std::string Agent::handleStatusRequest() {
    std::lock_guard<std::mutex> lock(stateMutex_);

    // Get system metrics
    double cpu_usage = 0.0;
    double memory_usage = 0.0;

    if (monitor_) {
        cpu_usage = monitor_->getCpuUsage();
        memory_usage = monitor_->getMemoryUsage();
    }

    std::stringstream metrics_json;
    metrics_json << "{";
    metrics_json << "\"cpu_usage\": " << std::fixed << std::setprecision(1) << cpu_usage << ",";
    metrics_json << "\"memory_usage\": " << std::fixed << std::setprecision(1) << memory_usage << ",";
    metrics_json << "\"network_packets\": 1250,";
    metrics_json << "\"threats_detected\": " << threats_detected_.load();
    metrics_json << "}";

    std::stringstream response;
    response << "HTTP/1.1 200 OK\r\n";
    response << "Content-Type: application/json\r\n";
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "\r\n";
    response << "{\"status\": \"running\", \"metrics\": " << metrics_json.str() << "}";

    return response.str();
}

std::string Agent::handleCommandRequest(const std::string& request) {
    // Extract command from POST body
    size_t body_start = request.find("\r\n\r\n");
    if (body_start == std::string::npos) {
        return "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\": \"Invalid request\"}";
    }

    std::string body = request.substr(body_start + 4);
    std::string command;

    // Simple JSON parsing for command
    size_t cmd_start = body.find("\"command\"");
    if (cmd_start != std::string::npos) {
        size_t value_start = body.find(":", cmd_start);
        size_t value_end = body.find("\"", value_start + 3);
        if (value_start != std::string::npos && value_end != std::string::npos) {
            command = body.substr(value_start + 3, value_end - value_start - 3);
        }
    }

    if (!command.empty()) {
        receiveRemoteCommand(command);
        std::stringstream response;
        response << "HTTP/1.1 200 OK\r\n";
        response << "Content-Type: application/json\r\n";
        response << "Access-Control-Allow-Origin: *\r\n";
        response << "\r\n";
        response << "{\"success\": true, \"message\": \"Command received: " << command << "\"}";
        return response.str();
    }

    return "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\": \"No command specified\"}";
}

std::string Agent::handleLogsRequest() {
    std::stringstream response;
    response << "HTTP/1.1 200 OK\r\n";
    response << "Content-Type: application/json\r\n";
    response << "Access-Control-Allow-Origin: *\r\n";
    response << "\r\n";

    try {
        std::ifstream logFile("aica_agent.log");
        if (logFile.is_open()) {
            std::string line;
            std::vector<std::pair<std::string, std::string>> logs;
            std::string current_timestamp;

            while (std::getline(logFile, line) && logs.size() < 50) {
                // Check if this is a timestamp line (doesn't start with ": ")
                if (line.find(": ") != 0) {
                    current_timestamp = line;
                } else {
                    // This is a message line, extract the message (remove leading ": ")
                    std::string message = line.substr(2);
                    logs.push_back(std::make_pair(current_timestamp, message));
                }
            }
            logFile.close();

            response << "[";
            for (size_t i = 0; i < logs.size(); ++i) {
                if (i > 0) response << ",";
                response << "{\"timestamp\": \"" << logs[i].first << "\", \"message\": \"" << logs[i].second << "\"}";
            }
            response << "]";
        } else {
            response << "[{\"timestamp\": \"\", \"message\": \"No logs available\"}]";
        }
    } catch (const std::exception& e) {
        response << "[{\"timestamp\": \"\", \"message\": \"Error reading logs: " << e.what() << "\"}]";
    }

    return response.str();
}

bool Agent::analyzeWithLLM(const std::vector<std::string>& observations) {
    try {
        // Prepare request to LLM backend
        std::stringstream json_payload;
        json_payload << "{\"action\": \"analyze_threat\", \"observations\": [";

        for (size_t i = 0; i < observations.size(); ++i) {
            json_payload << "\"" << observations[i] << "\"";
            if (i < observations.size() - 1) {
                json_payload << ",";
            }
        }
        json_payload << "]}";

        // Send HTTP request to LLM backend
        std::string llm_host = "localhost";
        int llm_port = 8081;

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return false;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(llm_port);
        inet_pton(AF_INET, llm_host.c_str(), &server_addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            return false; // LLM backend not available
        }

        // Send POST request
        std::string request = "POST /analyze_threat HTTP/1.1\r\n";
        request += "Host: " + llm_host + ":" + std::to_string(llm_port) + "\r\n";
        request += "Content-Type: application/json\r\n";
        request += "Content-Length: " + std::to_string(json_payload.str().length()) + "\r\n";
        request += "\r\n";
        request += json_payload.str();

        send(sock, request.c_str(), request.length(), 0);

        // Read response
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_read = read(sock, buffer, sizeof(buffer) - 1);
        close(sock);

        if (bytes_read <= 0) {
            logEvent("LLM Analysis: No response received from LLM backend");
            return false;
        }

        std::string response(buffer);

        // Log the LLM response
        logEvent("LLM Response: " + response);

        // Parse response for threat detection
        if (response.find("\"threat_level\": \"high\"") != std::string::npos ||
            response.find("\"threat_level\": \"medium\"") != std::string::npos) {
            std::cout << "LLM Analysis: Threat detected by AI analysis" << std::endl;
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        // LLM backend not available or error occurred
        return false;
    }
}

void Agent::logEvent(const std::string& event) {
    std::ofstream logFile("aica_agent.log", std::ios::app);
    if (logFile.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        logFile << std::ctime(&time) << ": " << event << std::endl;
    }
}

} // namespace CDA
