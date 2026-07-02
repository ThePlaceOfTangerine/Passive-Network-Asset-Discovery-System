#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "AssetEvent.hpp"

class ArpParser {
public:
    std::optional<AssetEvent> parse(const uint8_t* packet, int length, const std::string& iface);

private:
    std::string macToString(const uint8_t* mac);
    std::string ipToString(const uint8_t* ip);
    std::string nowIso();
    std::string randomId();
};
