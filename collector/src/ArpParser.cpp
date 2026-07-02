#include "ArpParser.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct ArpHeader {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};
#pragma pack(pop)

std::optional<AssetEvent> ArpParser::parse(const uint8_t* packet, int length, const std::string& iface) {
    if (length < static_cast<int>(sizeof(EthernetHeader) + sizeof(ArpHeader))) {
        return std::nullopt;
    }

    const auto* eth = reinterpret_cast<const EthernetHeader*>(packet);
    uint16_t eth_type = ntohs(eth->eth_type);

    if (eth_type != 0x0806) {
        return std::nullopt;
    }

    const auto* arp = reinterpret_cast<const ArpHeader*>(packet + sizeof(EthernetHeader));

    uint16_t hardware_type = ntohs(arp->hardware_type);
    uint16_t protocol_type = ntohs(arp->protocol_type);
    uint16_t opcode = ntohs(arp->opcode);

    if (hardware_type != 1 || protocol_type != 0x0800) {
        return std::nullopt;
    }

    std::string sender_mac = macToString(arp->sender_mac);
    std::string sender_ip = ipToString(arp->sender_ip);
    std::string target_mac = macToString(arp->target_mac);
    std::string target_ip = ipToString(arp->target_ip);

    if (sender_ip == "0.0.0.0" || sender_mac == "00:00:00:00:00:00") {
        return std::nullopt;
    }

    std::string timestamp = nowIso();

    AssetEvent event;
    event.event_id = randomId();
    event.asset_id = sender_mac;
    event.ip = sender_ip;
    event.mac = sender_mac;
    event.hostname = "";
    event.vendor = "";
    event.source = "arp";
    event.confidence = 0.9;
    event.first_seen = timestamp;
    event.last_seen = timestamp;
    event.raw = {
        {"protocol", "arp"},
        {"interface", iface},
        {"operation", opcode == 1 ? "request" : opcode == 2 ? "reply" : "other"},
        {"target_mac", target_mac},
        {"target_ip", target_ip}
    };

    return event;
}

std::string ArpParser::macToString(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            oss << ":";
        }
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string ArpParser::ipToString(const uint8_t* ip) {
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip, buffer, sizeof(buffer));
    return std::string(buffer);
}

std::string ArpParser::nowIso() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
    gmtime_r(&time, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return oss.str();
}

std::string ArpParser::randomId() {
    static std::mt19937_64 rng(std::random_device{}());
    static std::uniform_int_distribution<unsigned long long> dist;

    std::ostringstream oss;
    oss << std::hex << dist(rng);
    return oss.str();
}
