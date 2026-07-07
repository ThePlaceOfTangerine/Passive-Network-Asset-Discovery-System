#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "AssetEvent.hpp"

class ProtocolParser {
public:
    virtual ~ProtocolParser() = default;

    virtual std::optional<AssetEvent> parse(
        const uint8_t* packet,
        int length,
        const std::string& sourceName
    ) = 0;

    virtual std::string name() const = 0;
};
