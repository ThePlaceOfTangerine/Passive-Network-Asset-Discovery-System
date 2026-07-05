#include "DhcpParser.hpp"

#include <arpa/inet.h>

#include <chrono>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct Ipv4Header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct DhcpFixedHeader {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint8_t ciaddr[4];
    uint8_t yiaddr[4];
    uint8_t siaddr[4];
    uint8_t giaddr[4];
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
};
#pragma pack(pop)

std::optional<AssetEvent> DhcpParser::parse(const uint8_t* packet, int length, const std::string& iface) {
    const int ethernetSize = static_cast<int>(sizeof(EthernetHeader));

    if (length < ethernetSize + static_cast<int>(sizeof(Ipv4Header) + sizeof(UdpHeader) + sizeof(DhcpFixedHeader) + 4)) {
        return std::nullopt;
    }

    const auto* eth = reinterpret_cast<const EthernetHeader*>(packet);
    uint16_t ethType = ntohs(eth->eth_type);

    if (ethType != 0x0800) {
        return std::nullopt;
    }

    const auto* ip = reinterpret_cast<const Ipv4Header*>(packet + ethernetSize);

    uint8_t version = ip->version_ihl >> 4;
    uint8_t ihl = ip->version_ihl & 0x0F;
    int ipHeaderLength = ihl * 4;

    if (version != 4 || ipHeaderLength < 20) {
        return std::nullopt;
    }

    if (length < ethernetSize + ipHeaderLength + static_cast<int>(sizeof(UdpHeader) + sizeof(DhcpFixedHeader) + 4)) {
        return std::nullopt;
    }

    if (ip->protocol != 17) {
        return std::nullopt;
    }

    const auto* udp = reinterpret_cast<const UdpHeader*>(packet + ethernetSize + ipHeaderLength);
    uint16_t srcPort = ntohs(udp->src_port);
    uint16_t dstPort = ntohs(udp->dst_port);

    bool isDhcpPort = (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68);
    if (!isDhcpPort) {
        return std::nullopt;
    }

    const uint8_t* dhcpStart = packet + ethernetSize + ipHeaderLength + sizeof(UdpHeader);
    int dhcpLength = length - ethernetSize - ipHeaderLength - static_cast<int>(sizeof(UdpHeader));

    if (dhcpLength < static_cast<int>(sizeof(DhcpFixedHeader) + 4)) {
        return std::nullopt;
    }

    const auto* dhcp = reinterpret_cast<const DhcpFixedHeader*>(dhcpStart);

    if (dhcp->htype != 1 || dhcp->hlen < 6) {
        return std::nullopt;
    }

    const uint8_t* cookie = dhcpStart + sizeof(DhcpFixedHeader);
    bool validCookie =
        cookie[0] == 0x63 &&
        cookie[1] == 0x82 &&
        cookie[2] == 0x53 &&
        cookie[3] == 0x63;

    if (!validCookie) {
        return std::nullopt;
    }

    std::string clientMac = macToString(dhcp->chaddr);
    if (clientMac == "00:00:00:00:00:00") {
        return std::nullopt;
    }

    std::string hostname;
    std::string vendorClass;
    std::string requestedIp;
    uint8_t dhcpMessageType = 0;

    const uint8_t* options = cookie + 4;
    int optionsLength = dhcpLength - static_cast<int>(sizeof(DhcpFixedHeader)) - 4;
    int offset = 0;

    while (offset < optionsLength) {
        uint8_t code = options[offset];

        if (code == 255) {
            break;
        }

        if (code == 0) {
            offset += 1;
            continue;
        }

        if (offset + 1 >= optionsLength) {
            break;
        }

        uint8_t optLen = options[offset + 1];

        if (offset + 2 + optLen > optionsLength) {
            break;
        }

        const uint8_t* value = options + offset + 2;

        if (code == 12) {
            hostname = bytesToString(value, optLen);
        } else if (code == 50 && optLen == 4) {
            requestedIp = ipToString(value);
        } else if (code == 53 && optLen == 1) {
            dhcpMessageType = value[0];
        } else if (code == 60) {
            vendorClass = bytesToString(value, optLen);
        }

        offset += 2 + optLen;
    }

    std::string ciaddr = ipToString(dhcp->ciaddr);
    std::string yiaddr = ipToString(dhcp->yiaddr);
    std::string srcIp = ipToString(ip->src_ip);
    std::string dstIp = ipToString(ip->dst_ip);

    std::string assetIp;

    if (!requestedIp.empty() && requestedIp != "0.0.0.0") {
        assetIp = requestedIp;
    } else if (yiaddr != "0.0.0.0") {
        assetIp = yiaddr;
    } else if (ciaddr != "0.0.0.0") {
        assetIp = ciaddr;
    } else if (srcIp != "0.0.0.0") {
        assetIp = srcIp;
    } else {
        assetIp = "";
    }

    std::string timestamp = nowIso();

    AssetEvent event;
    event.event_id = randomId();
    event.asset_id = clientMac;
    event.ip = assetIp;
    event.mac = clientMac;
    event.hostname = hostname;
    event.vendor = vendorClass;
    event.source = "dhcp";
    event.first_seen = timestamp;
    event.last_seen = timestamp;
    event.raw = {
        {"protocol", "dhcp"},
        {"interface", iface},
        {"message_type", messageTypeName(dhcpMessageType)},
        {"message_type_code", dhcpMessageType},
        {"src_ip", srcIp},
        {"dst_ip", dstIp},
        {"ciaddr", ciaddr},
        {"yiaddr", yiaddr},
        {"requested_ip", requestedIp},
        {"client_mac", clientMac},
        {"hostname", hostname},
        {"vendor_class", vendorClass}
    };

    return event;
}

std::string DhcpParser::macToString(const uint8_t* mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            oss << ":";
        }
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string DhcpParser::ipToString(const uint8_t* ip) {
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip, buffer, sizeof(buffer));
    return std::string(buffer);
}

std::string DhcpParser::nowIso() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
    gmtime_r(&time, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return oss.str();
}

std::string DhcpParser::randomId() {
    static std::mt19937_64 rng(std::random_device{}());
    static std::uniform_int_distribution<unsigned long long> dist;

    std::ostringstream oss;
    oss << std::hex << dist(rng);
    return oss.str();
}

std::string DhcpParser::bytesToString(const uint8_t* data, int length) {
    std::string value;

    for (int i = 0; i < length; ++i) {
        char c = static_cast<char>(data[i]);
        if (c >= 32 && c <= 126) {
            value.push_back(c);
        }
    }

    return value;
}

std::string DhcpParser::messageTypeName(uint8_t type) {
    switch (type) {
        case 1:
            return "discover";
        case 2:
            return "offer";
        case 3:
            return "request";
        case 4:
            return "decline";
        case 5:
            return "ack";
        case 6:
            return "nak";
        case 7:
            return "release";
        case 8:
            return "inform";
        default:
            return "unknown";
    }
}
