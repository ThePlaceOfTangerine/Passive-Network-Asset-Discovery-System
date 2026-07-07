#include "SsdpParser.hpp"

#include <arpa/inet.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>
#include <vector>

#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t etherType;
};

struct Ipv4Header {
    uint8_t versionIhl;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsFragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t srcIp[4];
    uint8_t dstIp[4];
};

struct UdpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

std::string SsdpParser::name() const {
    return "ssdp";
}

std::optional<AssetEvent> SsdpParser::parse(
    const uint8_t* packet,
    int length,
    const std::string& sourceName
) {
    if (length < static_cast<int>(sizeof(EthernetHeader) + sizeof(Ipv4Header) + sizeof(UdpHeader))) {
        return std::nullopt;
    }

    const auto* eth = reinterpret_cast<const EthernetHeader*>(packet);

    uint16_t etherType = ntohs(eth->etherType);
    if (etherType != 0x0800) {
        return std::nullopt;
    }

    const auto* ip = reinterpret_cast<const Ipv4Header*>(packet + sizeof(EthernetHeader));

    uint8_t version = ip->versionIhl >> 4;
    uint8_t ihl = ip->versionIhl & 0x0F;
    int ipHeaderLength = ihl * 4;

    if (version != 4 || ipHeaderLength < 20) {
        return std::nullopt;
    }

    if (ip->protocol != 17) {
        return std::nullopt;
    }

    int udpOffset = sizeof(EthernetHeader) + ipHeaderLength;

    if (length < udpOffset + static_cast<int>(sizeof(UdpHeader))) {
        return std::nullopt;
    }

    const auto* udp = reinterpret_cast<const UdpHeader*>(packet + udpOffset);

    uint16_t srcPort = ntohs(udp->srcPort);
    uint16_t dstPort = ntohs(udp->dstPort);

    if (srcPort != 1900 && dstPort != 1900) {
        return std::nullopt;
    }

    int payloadOffset = udpOffset + sizeof(UdpHeader);

    if (length <= payloadOffset) {
        return std::nullopt;
    }

    int payloadLength = length - payloadOffset;
    std::string payload(
        reinterpret_cast<const char*>(packet + payloadOffset),
        payloadLength
    );

    std::string lowerPayload = toLower(payload);

    if (
        lowerPayload.find("ssdp:") == std::string::npos &&
        lowerPayload.find("upnp:") == std::string::npos &&
        lowerPayload.find("m-search") == std::string::npos &&
        lowerPayload.find("notify") == std::string::npos
    ) {
        return std::nullopt;
    }

    auto headers = parseHeaders(payload);

    std::string firstLine;
    std::istringstream stream(payload);
    std::getline(stream, firstLine);
    firstLine = trim(firstLine);

    std::string srcMac = macToString(eth->src);
    std::string srcIp = ipToString(ip->srcIp);
    std::string now = nowIso();

    AssetEvent event;
    event.event_id = randomId();
    event.asset_id = srcMac;
    event.ip = srcIp;
    event.mac = srcMac;
    event.hostname = "";
    event.vendor = "";
    event.source = "ssdp";
    event.first_seen = now;
    event.last_seen = now;

    event.raw = {
        {"protocol", "ssdp"},
        {"interface", sourceName},
        {"src_port", srcPort},
        {"dst_port", dstPort},
        {"first_line", firstLine},
        {"server", headers.count("server") ? headers["server"] : ""},
        {"location", headers.count("location") ? headers["location"] : ""},
        {"nt", headers.count("nt") ? headers["nt"] : ""},
        {"nts", headers.count("nts") ? headers["nts"] : ""},
        {"st", headers.count("st") ? headers["st"] : ""},
        {"usn", headers.count("usn") ? headers["usn"] : ""}
    };

    return event;
}

std::string SsdpParser::macToString(const uint8_t* mac) {
    std::ostringstream oss;

    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            oss << ":";
        }

        oss << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(mac[i]);
    }

    return oss.str();
}

std::string SsdpParser::ipToString(const uint8_t* ip) {
    std::ostringstream oss;

    oss << static_cast<int>(ip[0]) << "."
        << static_cast<int>(ip[1]) << "."
        << static_cast<int>(ip[2]) << "."
        << static_cast<int>(ip[3]);

    return oss.str();
}

std::string SsdpParser::nowIso() {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);

    std::tm utcTime{};
    gmtime_r(&time, &utcTime);

    std::ostringstream oss;
    oss << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%S");

    return oss.str();
}

std::string SsdpParser::randomId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dist(0, 15);

    std::ostringstream oss;

    for (int i = 0; i < 16; ++i) {
        oss << std::hex << dist(gen);
    }

    return oss.str();
}

std::string SsdpParser::trim(const std::string& value) {
    const std::string whitespace = " \t\r\n";

    size_t start = value.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return "";
    }

    size_t end = value.find_last_not_of(whitespace);
    return value.substr(start, end - start + 1);
}

std::string SsdpParser::toLower(const std::string& value) {
    std::string result = value;

    for (char& ch : result) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }

    return result;
}

std::map<std::string, std::string> SsdpParser::parseHeaders(const std::string& payload) {
    std::map<std::string, std::string> headers;
    std::istringstream stream(payload);
    std::string line;

    while (std::getline(stream, line)) {
        line = trim(line);

        if (line.empty()) {
            continue;
        }

        size_t pos = line.find(':');
        if (pos == std::string::npos) {
            continue;
        }

        std::string key = toLower(trim(line.substr(0, pos)));
        std::string value = trim(line.substr(pos + 1));

        if (!key.empty()) {
            headers[key] = value;
        }
    }

    return headers;
}
