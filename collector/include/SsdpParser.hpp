#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "AssetEvent.hpp"
#include "ProtocolParser.hpp"

class SsdpParser : public ProtocolParser {
public:
    std::optional<AssetEvent> parse(
        const uint8_t* packet,
        int length,
        const std::string& sourceName
    ) override;

    std::string name() const override;

private:
    std::string macToString(const uint8_t* mac);
    std::string ipToString(const uint8_t* ip);
    std::string nowIso();
    std::string randomId();
    std::string trim(const std::string& value);
    std::string toLower(const std::string& value);
    std::map<std::string, std::string> parseHeaders(const std::string& payload);
};
