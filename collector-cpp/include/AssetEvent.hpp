#pragma once

#include <string>
#include <nlohmann/json.hpp>

struct AssetEvent {
    std::string event_id;
    std::string asset_id;
    std::string ip;
    std::string mac;
    std::string hostname;
    std::string vendor;
    std::string source;
    double confidence;
    std::string first_seen;
    std::string last_seen;
    nlohmann::json raw;

    nlohmann::json toJson() const {
        return {
            {"event_id", event_id},
            {"asset_id", asset_id},
            {"ip", ip},
            {"mac", mac},
            {"hostname", hostname},
            {"vendor", vendor},
            {"source", source},
            {"confidence", confidence},
            {"first_seen", first_seen},
            {"last_seen", last_seen},
            {"raw", raw}
        };
    }
};
