#ifndef PACKET_INSPECTOR_H
#define PACKET_INSPECTOR_H

#include <string>
#include <vector>
#include <memory>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace CDA {

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

class PacketInspector {
public:
    PacketInspector();
    ~PacketInspector();

    bool startInspection(const std::string& interface = "");
    void stopInspection();
    std::vector<PacketInfo> getRecentPackets();
    std::vector<std::string> getSuspiciousPackets();
    void setPacketFilter(const std::string& filter);

private:
    pcap_t* handle_;
    std::thread capture_thread_;
    std::atomic<bool> running_;
    std::mutex packets_mutex_;
    std::vector<PacketInfo> recent_packets_;
    std::vector<std::string> suspicious_packets_;
    std::string current_filter_;

    // Packet processing
    void packetHandler(const struct pcap_pkthdr* header, const u_char* packet);
    void processEthernetPacket(const u_char* packet, uint32_t length);
    void processIPPacket(const u_char* packet, uint32_t length);
    void processTCPPacket(const struct ip* ip_header, const u_char* packet, uint32_t length);
    void processUDPPacket(const struct ip* ip_header, const u_char* packet, uint32_t length);
    void processICMPPacket(const struct ip* ip_header, const u_char* packet, uint32_t length);

    // Threat detection
    bool inspectPayload(const u_char* payload, uint32_t length, const std::string& protocol);
    bool detectMaliciousPatterns(const u_char* data, uint32_t length);
    bool detectSQLInjection(const u_char* data, uint32_t length);
    bool detectXSS(const u_char* data, uint32_t length);
    bool detectCommandInjection(const u_char* data, uint32_t length);
    bool detectSuspiciousPorts(uint16_t port);
    bool detectAnomalousTraffic(const PacketInfo& packet);

    // Utility functions
    std::string getDefaultInterface();
    std::string ipToString(uint32_t ip);
    std::string extractPayloadSample(const u_char* payload, uint32_t length);
    void logSuspiciousPacket(const PacketInfo& packet);

    // Statistics
    std::unordered_map<std::string, uint32_t> protocol_counts_;
    std::unordered_map<std::string, uint32_t> suspicious_counts_;
    uint32_t total_packets_;
    uint32_t suspicious_packets_count_;

    static void pcapCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
};

} // namespace CDA

#endif // PACKET_INSPECTOR_H
