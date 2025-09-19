#include "CDA.h"
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <regex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>

namespace CDA {

class MalwareDetector : public Detector {
public:
    MalwareDetector() {
        loadMalwareSignatures();
        loadFileSignatures();
        initializeBehavioralPatterns();
    }

    bool detectMalware(const std::vector<std::string>& observations) override {
        bool threatDetected = false;

        for (const auto& observation : observations) {
            // Check for signature-based detection
            if (scanForSignatures(observation)) {
                std::cout << "Malware signature detected in: " << observation << std::endl;
                threatDetected = true;
            }

            // Check for behavioral anomalies
            if (detectBehavioralAnomaly(observation)) {
                std::cout << "Behavioral anomaly detected in: " << observation << std::endl;
                threatDetected = true;
            }

            // Check for file-based threats
            if (observation.find("Files:") != std::string::npos) {
                std::vector<std::string> files = extractFilePaths(observation);
                for (const auto& file : files) {
                    if (scanFileForMalware(file)) {
                        std::cout << "Malware detected in file: " << file << std::endl;
                        threatDetected = true;
                    }
                }
            }

            // Check for network-based threats
            if (observation.find("Network:") != std::string::npos) {
                if (detectNetworkAnomaly(observation)) {
                    std::cout << "Network anomaly detected in: " << observation << std::endl;
                    threatDetected = true;
                }
            }
        }

        return threatDetected;
    }

    std::string classifyThreat(const std::string& observation) override {
        // Advanced threat classification
        if (isTrojan(observation)) {
            return "Trojan";
        } else if (isVirus(observation)) {
            return "Virus";
        } else if (isWorm(observation)) {
            return "Worm";
        } else if (isRansomware(observation)) {
            return "Ransomware";
        } else if (isSpyware(observation)) {
            return "Spyware";
        } else if (isRootkit(observation)) {
            return "Rootkit";
        } else if (isBackdoor(observation)) {
            return "Backdoor";
        } else {
            return "Unknown";
        }
    }

private:
    std::vector<std::string> malwareSignatures_;
    std::vector<std::string> fileSignatures_;
    std::vector<std::string> behavioralPatterns_;
    std::unordered_map<std::string, std::string> signatureDatabase_;

    void loadMalwareSignatures() {
        // Load comprehensive malware signatures
        malwareSignatures_ = {
            // Common malware signatures
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "MZ", // Windows executable signature
            "#!/bin/bash", // Shell script
            "powershell", // PowerShell
            "cmd.exe", // Command prompt
            "netcat", "nc", "ncat", // Network utilities
            "wget", "curl", // Download tools
            "base64", // Encoding
            "chmod +x", // Permission changes
            "sudo", "su", // Privilege escalation
            "cryptominer", "miner", "xmrig",
            "backdoor", "trojan", "virus", "worm",
            "keylogger", "spyware", "ransomware",
            "botnet", "c2", "command_and_control"
        };
    }

    void loadFileSignatures() {
        // File-based signatures (MD5 hashes of known malware)
        fileSignatures_ = {
            // Example signatures - in real implementation, load from database
            "d41d8cd98f00b204e9800998ecf8427e", // Empty file MD5
            // Add real malware hashes here
        };
    }

    void initializeBehavioralPatterns() {
        behavioralPatterns_ = {
            "unusual_network_activity",
            "suspicious_file_modification",
            "abnormal_process_behavior",
            "privilege_escalation_attempt",
            "suspicious_system_calls",
            "anomalous_file_access",
            "unusual_login_attempts",
            "suspicious_registry_changes"
        };
    }

    bool scanForSignatures(const std::string& data) {
        for (const auto& signature : malwareSignatures_) {
            if (data.find(signature) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool detectBehavioralAnomaly(const std::string& observation) {
        for (const auto& pattern : behavioralPatterns_) {
            if (observation.find(pattern) != std::string::npos) {
                return true;
            }
        }

        // Advanced behavioral analysis
        if (containsSuspiciousKeywords(observation)) {
            return true;
        }

        if (detectsAnomalousPatterns(observation)) {
            return true;
        }

        return false;
    }

    bool containsSuspiciousKeywords(const std::string& data) {
        std::vector<std::string> suspicious_keywords = {
            "eval", "exec", "system", "shell_exec",
            "passthru", "popen", "proc_open",
            "base64_decode", "gzinflate", "str_rot13",
            "chmod", "chown", "unlink", "rmdir",
            "fopen", "fwrite", "file_put_contents",
            "mysql_connect", "mysqli_connect",
            "socket_create", "fsockopen",
            "mail", "sendmail"
        };

        for (const auto& keyword : suspicious_keywords) {
            if (data.find(keyword) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool detectsAnomalousPatterns(const std::string& data) {
        // Check for obfuscated code patterns
        if (data.find("eval(") != std::string::npos &&
            (data.find("base64") != std::string::npos ||
             data.find("gzinflate") != std::string::npos)) {
            return true;
        }

        // Check for suspicious file extensions
        std::vector<std::string> suspicious_extensions = {
            ".exe", ".bat", ".cmd", ".scr", ".pif", ".com",
            ".vbs", ".js", ".jar", ".ps1", ".sh"
        };

        for (const auto& ext : suspicious_extensions) {
            if (data.find(ext) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    std::vector<std::string> extractFilePaths(const std::string& observation) {
        std::vector<std::string> files;
        std::istringstream iss(observation);
        std::string token;

        while (std::getline(iss, token, '|')) {
            if (token.find("SUSPICIOUS:") != std::string::npos) {
                size_t pos = token.find("SUSPICIOUS:");
                std::string filepath = token.substr(pos + 12);
                // Trim whitespace
                filepath.erase(filepath.begin(),
                    std::find_if(filepath.begin(), filepath.end(),
                    [](int ch) { return !std::isspace(ch); }));
                files.push_back(filepath);
            }
        }

        return files;
    }

    bool scanFileForMalware(const std::string& filepath) {
        // Check file existence and permissions
        struct stat file_stat;
        if (stat(filepath.c_str(), &file_stat) != 0) {
            return false; // File doesn't exist or can't access
        }

        // Scan file content for signatures
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());

        if (scanForSignatures(content)) {
            return true;
        }

        // Check file hash against known malware
        std::string file_hash = calculateMD5(filepath);
        for (const auto& signature : fileSignatures_) {
            if (file_hash == signature) {
                return true;
            }
        }

        return false;
    }

    std::string calculateMD5(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }

        MD5_CTX md5_ctx;
        MD5_Init(&md5_ctx);

        char buffer[4096];
        while (file.read(buffer, sizeof(buffer))) {
            MD5_Update(&md5_ctx, buffer, file.gcount());
        }
        MD5_Update(&md5_ctx, buffer, file.gcount());

        unsigned char hash[MD5_DIGEST_LENGTH];
        MD5_Final(hash, &md5_ctx);

        std::stringstream ss;
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        return ss.str();
    }

    bool detectNetworkAnomaly(const std::string& observation) {
        // Check for suspicious network patterns
        if (observation.find("SUSPICIOUS:") != std::string::npos) {
            return true;
        }

        // Check for unusual connection patterns
        std::vector<std::string> suspicious_network_patterns = {
            "unusual port", "suspicious connection",
            "anomalous traffic", "unexpected connection"
        };

        for (const auto& pattern : suspicious_network_patterns) {
            if (observation.find(pattern) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    bool isTrojan(const std::string& data) {
        return data.find("trojan") != std::string::npos ||
               (data.find("backdoor") != std::string::npos &&
                data.find("remote") != std::string::npos);
    }

    bool isVirus(const std::string& data) {
        return data.find("virus") != std::string::npos ||
               data.find("self-replicating") != std::string::npos;
    }

    bool isWorm(const std::string& data) {
        return data.find("worm") != std::string::npos ||
               (data.find("network") != std::string::npos &&
                data.find("spreading") != std::string::npos);
    }

    bool isRansomware(const std::string& data) {
        return data.find("ransomware") != std::string::npos ||
               data.find("encrypt") != std::string::npos ||
               data.find("bitcoin") != std::string::npos;
    }

    bool isSpyware(const std::string& data) {
        return data.find("spyware") != std::string::npos ||
               data.find("keylogger") != std::string::npos ||
               data.find("monitoring") != std::string::npos;
    }

    bool isRootkit(const std::string& data) {
        return data.find("rootkit") != std::string::npos ||
               data.find("hide") != std::string::npos ||
               data.find("kernel") != std::string::npos;
    }

    bool isBackdoor(const std::string& data) {
        return data.find("backdoor") != std::string::npos ||
               data.find("reverse_shell") != std::string::npos ||
               data.find("c2") != std::string::npos;
    }
};

// Factory function to create detector
std::unique_ptr<Detector> createDetector() {
    return std::make_unique<MalwareDetector>();
}

} // namespace CDA
