#include "PacketInspector.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>

namespace CDA {

PacketInspector::PacketInspector()
    : handle_(nullptr), running_(false), total_packets_(0), suspicious_packets_count_(0) {
}

PacketInspector::~PacketInspector() {
    stopInspection();
}

bool PacketInspector::startInspection(const std::string& interface) {
    if (running_) return false;

    std::string dev = interface.empty() ? getDefaultInterface() : interface;

    if (dev.empty()) {
        std::cerr << "No suitable network interface found" << std::endl;
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle_ == nullptr) {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return false;
    }

    // Set filter if specified
    if (!current_filter_.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle_, &fp, current_filter_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Couldn't parse filter " << current_filter_ << ": " << pcap_geterr(handle_) << std::endl;
            return false;
        }
        if (pcap_setfilter(handle_, &fp) == -1) {
            std::cerr << "Couldn't install filter " << current_filter_ << ": " << pcap_geterr(handle_) << std::endl;
            return false;
        }
        pcap_freecode(&fp);
    }

    running_ = true;
    capture_thread_ = std::thread([this]() {
        pcap_loop(handle_, 0, pcapCallback, reinterpret_cast<u_char*>(this));
    });

    std::cout << "Packet inspection started on interface: " << dev << std::endl;
    return true;
}

void PacketInspector::stopInspection() {
    if (!running_) return;

    running_ = false;
    if (handle_) {
        pcap_breakloop(handle_);
    }

    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }

    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }

    std::cout << "Packet inspection stopped" << std::endl;
}

std::vector<PacketInfo> PacketInspector::getRecentPackets() {
    std::lock_guard<std::mutex> lock(packets_mutex_);
    return recent_packets_;
}

std::vector<std::string> PacketInspector::getSuspiciousPackets() {
    std::lock_guard<std::mutex> lock(packets_mutex_);
    return suspicious_packets_;
}

void PacketInspector::setPacketFilter(const std::string& filter) {
    current_filter_ = filter;
}

void PacketInspector::pcapCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketInspector* inspector = reinterpret_cast<PacketInspector*>(user);
    inspector->packetHandler(header, packet);
}

void PacketInspector::packetHandler(const struct pcap_pkthdr* header, const u_char* packet) {
    total_packets_++;

    // Get timestamp
    time_t now = header->ts.tv_sec;
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    PacketInfo info;
    info.timestamp = timestamp;
    info.packet_size = header->len;
    info.suspicious = false;
    info.source_ip = "";
    info.dest_ip = "";
    info.source_port = 0;
    info.dest_port = 0;
    info.protocol = "Unknown";
    info.payload_sample = "";
    info.threat_type = "";

    // Process Ethernet frame
    processEthernetPacket(packet, header->len);

    // Store packet info only if it wasn't already stored by protocol handlers
    // Check if we have any recent packets with the same timestamp
    std::lock_guard<std::mutex> lock(packets_mutex_);
    bool already_stored = false;
    if (!recent_packets_.empty()) {
        // Check the last packet to see if it was stored by a protocol handler
        const PacketInfo& last_packet = recent_packets_.back();
        if (last_packet.timestamp == info.timestamp &&
            last_packet.packet_size == info.packet_size) {
            already_stored = true;
        }
    }

    if (!already_stored) {
        recent_packets_.push_back(info);
    }

    // Keep only last 100 packets
    if (recent_packets_.size() > 100) {
        recent_packets_.erase(recent_packets_.begin());
    }
}

void PacketInspector::processEthernetPacket(const u_char* packet, uint32_t length) {
    if (length < sizeof(struct ether_header)) {
        return;
    }

    const struct ether_header* ethernet = reinterpret_cast<const struct ether_header*>(packet);
    uint16_t ether_type = ntohs(ethernet->ether_type);

    // Check for IP packets
    if (ether_type == ETHERTYPE_IP) {
        const u_char* ip_packet = packet + sizeof(struct ether_header);
        processIPPacket(ip_packet, length - sizeof(struct ether_header));
    }
}

void PacketInspector::processIPPacket(const u_char* packet, uint32_t length) {
    if (length < sizeof(struct ip)) {
        return;
    }

    const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet);

    PacketInfo info;
    info.source_ip = inet_ntoa(ip_header->ip_src);
    info.dest_ip = inet_ntoa(ip_header->ip_dst);
    info.protocol = "IP";
    info.source_port = 0;
    info.dest_port = 0;
    info.payload_sample = "";
    info.suspicious = false;
    info.threat_type = "";

    protocol_counts_["IP"]++;

    // Process based on protocol
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            processTCPPacket(ip_header, packet + (ip_header->ip_hl * 4), length - (ip_header->ip_hl * 4));
            return; // TCP handler will store its own PacketInfo
        case IPPROTO_UDP:
            processUDPPacket(ip_header, packet + (ip_header->ip_hl * 4), length - (ip_header->ip_hl * 4));
            return; // UDP handler will store its own PacketInfo
        case IPPROTO_ICMP:
            processICMPPacket(ip_header, packet + (ip_header->ip_hl * 4), length - (ip_header->ip_hl * 4));
            return; // ICMP handler will store its own PacketInfo
        default:
            // For other IP protocols, store the basic IP packet info
            break;
    }

    // Store packet info for non-TCP/UDP/ICMP IP packets
    std::lock_guard<std::mutex> lock(packets_mutex_);
    recent_packets_.push_back(info);
}

void PacketInspector::processTCPPacket(const struct ip* ip_header, const u_char* packet, uint32_t length) {
    if (length < sizeof(struct tcphdr)) {
        return;
    }

    const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet);

    PacketInfo info;
    info.source_ip = inet_ntoa(ip_header->ip_src);
    info.dest_ip = inet_ntoa(ip_header->ip_dst);
    info.source_port = ntohs(tcp_header->th_sport);
    info.dest_port = ntohs(tcp_header->th_dport);
    info.protocol = "TCP";

    protocol_counts_["TCP"]++;

    // Check for suspicious ports
    if (detectSuspiciousPorts(info.source_port) || detectSuspiciousPorts(info.dest_port)) {
        info.suspicious = true;
        info.threat_type = "Suspicious Port";
        logSuspiciousPacket(info);
    }

    // Inspect payload
    uint32_t header_size = tcp_header->th_off * 4;
    if (length > header_size) {
        const u_char* payload = packet + header_size;
        uint32_t payload_length = length - header_size;

        info.payload_sample = extractPayloadSample(payload, payload_length);

        if (inspectPayload(payload, payload_length, "TCP")) {
            info.suspicious = true;
            info.threat_type = "Malicious Payload";
            logSuspiciousPacket(info);
        }
    }

    // Store packet info
    std::lock_guard<std::mutex> lock(packets_mutex_);
    recent_packets_.push_back(info);
}

void PacketInspector::processUDPPacket(const struct ip* ip_header, const u_char* packet, uint32_t length) {
    if (length < sizeof(struct udphdr)) {
        return;
    }

    const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(packet);

    PacketInfo info;
    info.source_ip = inet_ntoa(ip_header->ip_src);
    info.dest_ip = inet_ntoa(ip_header->ip_dst);
    info.source_port = ntohs(udp_header->uh_sport);
    info.dest_port = ntohs(udp_header->uh_dport);
    info.protocol = "UDP";

    protocol_counts_["UDP"]++;

    // Check for suspicious ports
    if (detectSuspiciousPorts(info.source_port) || detectSuspiciousPorts(info.dest_port)) {
        info.suspicious = true;
        info.threat_type = "Suspicious Port";
        logSuspiciousPacket(info);
    }

    // Inspect payload
    uint32_t header_size = sizeof(struct udphdr);
    if (length > header_size) {
        const u_char* payload = packet + header_size;
        uint32_t payload_length = length - header_size;

        info.payload_sample = extractPayloadSample(payload, payload_length);

        if (inspectPayload(payload, payload_length, "UDP")) {
            info.suspicious = true;
            info.threat_type = "Malicious Payload";
            logSuspiciousPacket(info);
        }
    }

    // Store packet info
    std::lock_guard<std::mutex> lock(packets_mutex_);
    recent_packets_.push_back(info);
}

void PacketInspector::processICMPPacket(const struct ip* ip_header, const u_char* packet, uint32_t length) {
    PacketInfo info;
    info.source_ip = inet_ntoa(ip_header->ip_src);
    info.dest_ip = inet_ntoa(ip_header->ip_dst);
    info.protocol = "ICMP";

    protocol_counts_["ICMP"]++;

    // ICMP packets can contain malicious payloads
    if (length > sizeof(struct icmp)) {
        const u_char* payload = packet + sizeof(struct icmp);
        uint32_t payload_length = length - sizeof(struct icmp);

        info.payload_sample = extractPayloadSample(payload, payload_length);

        if (inspectPayload(payload, payload_length, "ICMP")) {
            info.suspicious = true;
            info.threat_type = "Malicious ICMP Payload";
            logSuspiciousPacket(info);
        }
    }

    // Store packet info
    std::lock_guard<std::mutex> lock(packets_mutex_);
    recent_packets_.push_back(info);
}

bool PacketInspector::inspectPayload(const u_char* payload, uint32_t length, const std::string& protocol) {
    if (length == 0) return false;

    // Convert to string for easier processing
    std::string data(reinterpret_cast<const char*>(payload), length);

    // Check for various malicious patterns
    if (detectMaliciousPatterns(payload, length)) {
        return true;
    }

    if (detectSQLInjection(payload, length)) {
        return true;
    }

    if (detectXSS(payload, length)) {
        return true;
    }

    if (detectCommandInjection(payload, length)) {
        return true;
    }

    return false;
}

bool PacketInspector::detectMaliciousPatterns(const u_char* data, uint32_t length) {
    if (length < 4) return false;

    // Common malware signatures in packets
    const char* signatures[] = {
        "MZ",           // Windows executable
        "#!/bin/bash",  // Shell script
        "powershell",   // PowerShell
        "cmd.exe",      // Command prompt
        "eval(",        // PHP/JS eval
        "base64",       // Base64 encoding
        "<?php",        // PHP code
        "<script>",     // JavaScript
        "SELECT * FROM", // SQL query
        "UNION SELECT",  // SQL injection
        "DROP TABLE",    // SQL injection
        "script src=",   // XSS
        "javascript:",   // XSS
        "onload=",       // XSS
        "onerror=",      // XSS
        nullptr
    };

    std::string packet_data(reinterpret_cast<const char*>(data), length);

    for (int i = 0; signatures[i] != nullptr; ++i) {
        if (packet_data.find(signatures[i]) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool PacketInspector::detectSQLInjection(const u_char* data, uint32_t length) {
    std::string packet_data(reinterpret_cast<const char*>(data), length);

    // SQL injection patterns
    const char* sql_patterns[] = {
        "UNION SELECT",
        "UNION ALL SELECT",
        "ORDER BY",
        "GROUP BY",
        "HAVING",
        "OR 1=1",
        "OR '1'='1'",
        "OR \"1\"=\"1\"",
        "DROP TABLE",
        "DELETE FROM",
        "UPDATE users SET",
        "INSERT INTO",
        "--",
        "#",
        "/*",
        "*/",
        nullptr
    };

    for (int i = 0; sql_patterns[i] != nullptr; ++i) {
        if (packet_data.find(sql_patterns[i]) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool PacketInspector::detectXSS(const u_char* data, uint32_t length) {
    std::string packet_data(reinterpret_cast<const char*>(data), length);

    // XSS patterns
    const char* xss_patterns[] = {
        "<script",
        "javascript:",
        "vbscript:",
        "onload=",
        "onerror=",
        "onclick=",
        "onmouseover=",
        "onmouseout=",
        "onkeydown=",
        "onkeyup=",
        "onkeypress=",
        "<iframe",
        "<object",
        "<embed",
        "document.cookie",
        "document.location",
        "window.location",
        nullptr
    };

    for (int i = 0; xss_patterns[i] != nullptr; ++i) {
        if (packet_data.find(xss_patterns[i]) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool PacketInspector::detectCommandInjection(const u_char* data, uint32_t length) {
    std::string packet_data(reinterpret_cast<const char*>(data), length);

    // Command injection patterns
    const char* cmd_patterns[] = {
        "|",
        ";",
        "`",
        "$(",
        "${",
        "&&",
        "||",
        ">",
        "<",
        "2>&1",
        "/dev/null",
        "/bin/sh",
        "/bin/bash",
        "wget",
        "curl",
        "nc",
        "netcat",
        "python",
        "perl",
        "ruby",
        nullptr
    };

    for (int i = 0; cmd_patterns[i] != nullptr; ++i) {
        if (packet_data.find(cmd_patterns[i]) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool PacketInspector::detectSuspiciousPorts(uint16_t port) {
    // Known suspicious/malicious ports
    const uint16_t suspicious_ports[] = {
        22,    // SSH (often brute-forced)
        23,    // Telnet (insecure)
        445,   // SMB (vulnerable to exploits)
        1433,  // MSSQL
        1521,  // Oracle
        3306,  // MySQL
        3389,  // RDP
        4444,  // Common backdoor port
        6666,  // Common IRC/backdoor port
        6667,  // IRC
        8080,  // HTTP alternate
        8443,  // HTTPS alternate
        0      // End marker
    };

    for (int i = 0; suspicious_ports[i] != 0; ++i) {
        if (port == suspicious_ports[i]) {
            return true;
        }
    }

    return false;
}

bool PacketInspector::detectAnomalousTraffic(const PacketInfo& packet) {
    // Check for unusual traffic patterns
    if (packet.packet_size > 1500) {  // Jumbo packets
        return true;
    }

    if (packet.source_port == 0 || packet.dest_port == 0) {
        return true;
    }

    // Check for suspicious IP ranges
    if (packet.source_ip.find("127.") == 0 && packet.dest_ip.find("127.") != 0) {
        // Local traffic going outside
        return true;
    }

    return false;
}

std::string PacketInspector::getDefaultInterface() {
    struct ifaddrs* ifaddr, *ifa;
    char* interface = nullptr;

    if (getifaddrs(&ifaddr) == -1) {
        return "";
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        if (ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            interface = ifa->ifa_name;
            break;
        }
    }

    std::string result = interface ? interface : "";
    freeifaddrs(ifaddr);
    return result;
}

std::string PacketInspector::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

std::string PacketInspector::extractPayloadSample(const u_char* payload, uint32_t length) {
    if (length == 0) return "";

    uint32_t sample_length = std::min(length, static_cast<uint32_t>(50));
    std::string sample(reinterpret_cast<const char*>(payload), sample_length);

    // Replace non-printable characters
    for (char& c : sample) {
        if (!isprint(c) && !isspace(c)) {
            c = '.';
        }
    }

    return sample;
}

void PacketInspector::logSuspiciousPacket(const PacketInfo& packet) {
    suspicious_packets_count_++;
    suspicious_counts_[packet.threat_type]++;

    std::stringstream ss;
    ss << "[" << packet.timestamp << "] " << packet.threat_type << ": "
       << packet.source_ip << ":" << packet.source_port << " -> "
       << packet.dest_ip << ":" << packet.dest_port << " (" << packet.protocol << ")";

    std::lock_guard<std::mutex> lock(packets_mutex_);
    suspicious_packets_.push_back(ss.str());

    // Keep only last 50 suspicious packets
    if (suspicious_packets_.size() > 50) {
        suspicious_packets_.erase(suspicious_packets_.begin());
    }

    std::cout << "SUSPICIOUS PACKET: " << ss.str() << std::endl;
}

} // namespace CDA
