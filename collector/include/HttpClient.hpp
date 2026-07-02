#pragma once

#include <string>
#include <vector>

#include "AssetEvent.hpp"

class HttpClient {
public:
    explicit HttpClient(std::string endpoint);
    bool postEvents(const std::vector<AssetEvent>& events);

private:
    std::string endpoint_;
};
