#include "CDA.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <filesystem>
#include <algorithm>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>

namespace fs = std::filesystem;

namespace CDA {

class SystemMonitor : public Monitor {
public:
    SystemMonitor() : monitoring_(false) {}
    ~SystemMonitor() { stopMonitoring(); }

    void startMonitoring() override {
        if (monitoring_) return;

        monitoring_ = true;
        std::cout << "System monitoring started..." << std::endl;
    }

    void stopMonitoring() override {
        monitoring_ = false;
        std::cout << "System monitoring stopped." << std::endl;
    }

    std::vector<std::string> getObservations() override {
        std::vector<std::string> observations;

        // Monitor running processes
        observations.push_back("Processes: " + getRunningProcesses());

        // Monitor network connections
        observations.push_back("Network: " + getNetworkConnections());

        // Monitor file system changes
        observations.push_back("Files: " + getFileSystemChanges());

        // Monitor system logs
        observations.push_back("Logs: " + getSystemLogs());

        return observations;
    }

    double getCpuUsage() {
        return calculateCpuUsage();
    }

    double getMemoryUsage() {
        return calculateMemoryUsage();
    }

private:
    bool monitoring_;

    std::string getRunningProcesses() {
        std::vector<std::string> processes = scanProcesses();
        std::string result = "Active processes: " + std::to_string(processes.size());

        // Check for suspicious processes
        for (const auto& proc : processes) {
            if (isSuspiciousProcess(proc)) {
                result += " | SUSPICIOUS: " + proc;
            }
        }

        return result;
    }

    std::string getNetworkConnections() {
        std::vector<std::string> connections = scanNetworkConnections();
        std::string result = "Network connections: " + std::to_string(connections.size());

        // Check for suspicious connections
        for (const auto& conn : connections) {
            if (isSuspiciousConnection(conn)) {
                result += " | SUSPICIOUS: " + conn;
            }
        }

        return result;
    }

    std::string getFileSystemChanges() {
        std::vector<std::string> changes = scanFileSystem();
        std::string result = "File system changes: " + std::to_string(changes.size());

        // Check for suspicious file changes
        for (const auto& change : changes) {
            if (isSuspiciousFileChange(change)) {
                result += " | SUSPICIOUS: " + change;
            }
        }

        return result;
    }

    std::string getSystemLogs() {
        std::vector<std::string> anomalies = scanSystemLogs();
        std::string result = "Log anomalies: " + std::to_string(anomalies.size());

        if (!anomalies.empty()) {
            result += " | DETECTED: " + anomalies[0];
        }

        return result;
    }

    std::vector<std::string> scanProcesses() {
        std::vector<std::string> processes;

        DIR* dir = opendir("/proc");
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) {
                if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
                    std::string pid = entry->d_name;
                    std::string cmdline = getProcessCmdline(pid);
                    if (!cmdline.empty()) {
                        processes.push_back(cmdline);
                    }
                }
            }
            closedir(dir);
        }

        return processes;
    }

    std::string getProcessCmdline(const std::string& pid) {
        std::ifstream cmdfile("/proc/" + pid + "/cmdline");
        std::string cmdline;
        if (cmdfile.is_open()) {
            std::getline(cmdfile, cmdline);
            // Replace null bytes with spaces
            std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
        }
        return cmdline;
    }

    bool isSuspiciousProcess(const std::string& process) {
        std::vector<std::string> suspicious_patterns = {
            "nc", "netcat", "ncat", "socat", "cryptominer", "miner",
            "backdoor", "trojan", "malware", "virus", "worm",
            "keylogger", "spyware", "ransomware"
        };

        for (const auto& pattern : suspicious_patterns) {
            if (process.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    std::vector<std::string> scanNetworkConnections() {
        std::vector<std::string> connections;

        // Read /proc/net/tcp for TCP connections
        std::ifstream tcpfile("/proc/net/tcp");
        std::string line;
        if (tcpfile.is_open()) {
            std::getline(tcpfile, line); // Skip header
            while (std::getline(tcpfile, line)) {
                std::istringstream iss(line);
                std::string token;
                std::vector<std::string> fields;

                while (std::getline(iss, token, ' ')) {
                    if (!token.empty()) {
                        fields.push_back(token);
                    }
                }

                if (fields.size() >= 8) {
                    std::string local_addr = hexToIp(fields[1]);
                    std::string remote_addr = hexToIp(fields[2]);
                    std::string state = getTcpState(std::stoi(fields[3], nullptr, 16));

                    connections.push_back(local_addr + " -> " + remote_addr + " [" + state + "]");
                }
            }
        }

        return connections;
    }

    std::string hexToIp(const std::string& hex_addr) {
        std::istringstream iss(hex_addr);
        std::string ip_hex, port_hex;
        std::getline(iss, ip_hex, ':');
        std::getline(iss, port_hex, ':');

        unsigned int ip_int = std::stoul(ip_hex, nullptr, 16);
        unsigned int port_int = std::stoul(port_hex, nullptr, 16);

        struct in_addr addr;
        addr.s_addr = htonl(ip_int);

        char* ip_str = inet_ntoa(addr);
        return std::string(ip_str) + ":" + std::to_string(port_int);
    }

    std::string getTcpState(int state) {
        std::vector<std::string> states = {
            "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
            "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT",
            "LAST_ACK", "LISTEN", "CLOSING"
        };

        if (state >= 1 && state <= 11) {
            return states[state - 1];
        }
        return "UNKNOWN";
    }

    bool isSuspiciousConnection(const std::string& connection) {
        // Check for connections to known malicious ports or unusual patterns
        std::vector<std::string> suspicious_ports = {
            ":22 ", ":23 ", ":445 ", ":3389 ", ":4444 ", ":6666 ", ":6667 "
        };

        for (const auto& port : suspicious_ports) {
            if (connection.find(port) != std::string::npos) {
                return true;
            }
        }

        // Check for connections to suspicious IP ranges
        if (connection.find("10.0.0.") != std::string::npos ||
            connection.find("192.168.") != std::string::npos) {
            // Internal connections are generally okay
            return false;
        }

        return false;
    }

    std::vector<std::string> scanFileSystem() {
        std::vector<std::string> changes;

        // Monitor common system directories for changes
        std::vector<std::string> watch_dirs = {
            "/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"
        };

        for (const auto& dir : watch_dirs) {
            std::vector<std::string> dir_changes = scanDirectory(dir);
            changes.insert(changes.end(), dir_changes.begin(), dir_changes.end());
        }

        return changes;
    }

    std::vector<std::string> scanDirectory(const std::string& path) {
        std::vector<std::string> changes;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(path)) {
                if (fs::is_regular_file(entry)) {
                    auto file_time = fs::last_write_time(entry);
                    auto now = fs::file_time_type::clock::now();

                    // Check if file was modified recently (within last minute)
                    auto diff = now - file_time;
                    if (diff < std::chrono::minutes(1)) {
                        changes.push_back(entry.path().string());
                    }
                }
            }
        } catch (const std::exception& e) {
            // Ignore permission errors
        }

        return changes;
    }

    bool isSuspiciousFileChange(const std::string& filepath) {
        std::vector<std::string> suspicious_paths = {
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/usr/bin/ssh", "/usr/sbin/sshd",
            "/bin/bash", "/bin/sh"
        };

        for (const auto& path : suspicious_paths) {
            if (filepath.find(path) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    std::vector<std::string> scanSystemLogs() {
        std::vector<std::string> anomalies;

        std::vector<std::string> log_files = {
            "/var/log/auth.log", "/var/log/syslog", "/var/log/messages"
        };

        for (const auto& logfile : log_files) {
            std::vector<std::string> log_anomalies = scanLogFile(logfile);
            anomalies.insert(anomalies.end(), log_anomalies.begin(), log_anomalies.end());
        }

        return anomalies;
    }

    std::vector<std::string> scanLogFile(const std::string& filepath) {
        std::vector<std::string> anomalies;

        std::ifstream logfile(filepath);
        if (logfile.is_open()) {
            std::string line;
            while (std::getline(logfile, line)) {
                if (isSuspiciousLogEntry(line)) {
                    anomalies.push_back(line.substr(0, 100) + "..."); // Truncate long lines
                }
            }
        }

        return anomalies;
    }

    bool isSuspiciousLogEntry(const std::string& entry) {
        std::vector<std::string> suspicious_patterns = {
            "FAILED", "authentication failure", "invalid user",
            "POSSIBLE BREAK-IN", "ILLEGAL ROOT LOGIN",
            "suspicious", "malware", "trojan", "virus"
        };

        for (const auto& pattern : suspicious_patterns) {
            if (entry.find(pattern) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    double calculateCpuUsage() {
        std::ifstream stat_file("/proc/stat");
        std::string line;
        if (std::getline(stat_file, line)) {
            std::istringstream iss(line);
            std::string cpu_label;
            long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
            iss >> cpu_label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;

            long total_idle = idle + iowait;
            long total_non_idle = user + nice + system + irq + softirq + steal;
            long total = total_idle + total_non_idle;

            static long prev_total = 0;
            static long prev_idle = 0;

            long total_diff = total - prev_total;
            long idle_diff = total_idle - prev_idle;

            prev_total = total;
            prev_idle = total_idle;

            if (total_diff == 0) return 0.0;

            double cpu_usage = (double)(total_diff - idle_diff) / total_diff * 100.0;
            return std::max(0.0, std::min(100.0, cpu_usage));
        }
        return 0.0;
    }

    double calculateMemoryUsage() {
        std::ifstream meminfo("/proc/meminfo");
        std::string line;
        long total_memory = 0;
        long available_memory = 0;

        while (std::getline(meminfo, line)) {
            std::istringstream iss(line);
            std::string key;
            long value;
            std::string unit;
            iss >> key >> value >> unit;

            if (key == "MemTotal:") {
                total_memory = value;
            } else if (key == "MemAvailable:") {
                available_memory = value;
                break;
            }
        }

        if (total_memory == 0) return 0.0;

        long used_memory = total_memory - available_memory;
        double memory_usage = (double)used_memory / total_memory * 100.0;
        return std::max(0.0, std::min(100.0, memory_usage));
    }
};

// Factory function to create monitor
std::unique_ptr<Monitor> createMonitor() {
    return std::make_unique<SystemMonitor>();
}

} // namespace CDA
