#include "HttpClient.hpp"

#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>

HttpClient::HttpClient(std::string endpoint)
    : endpoint_(std::move(endpoint)) {}

bool HttpClient::postEvents(const std::vector<AssetEvent>& events) {
    if (events.empty()) {
        return true;
    }

    nlohmann::json payload = nlohmann::json::array();
    for (const auto& event : events) {
        payload.push_back(event.toJson());
    }

    std::string body = payload.dump();

    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize curl\n";
        return false;
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint_.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());

    CURLcode result = curl_easy_perform(curl);

    long status_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK) {
        std::cerr << "HTTP error: " << curl_easy_strerror(result) << "\n";
        return false;
    }

    std::cout << "Posted " << events.size()
              << " asset event(s), status=" << status_code << "\n";

    return status_code >= 200 && status_code < 300;
}
