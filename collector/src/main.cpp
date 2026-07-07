#include <pcap.h>

#include <csignal>
#include <chrono>
#include <exception>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <atomic>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <string>
#include <vector>

#include "ArpParser.hpp"
#include "DhcpParser.hpp"
#include "HttpClient.hpp"
#include "ProtocolParser.hpp"
#include "SsdpParser.hpp"

static bool running = true;

struct CollectorStats {
    int total_packets = 0;
    int parsed_asset_events = 0;
    int skipped_packets = 0;
    int sent_events = 0;
    int failed_sends = 0;
};

void handleSignal(int) {
    running = false;
}

std::string trim(const std::string& value) {
    const std::string whitespace = " \t\r\n";

    size_t start = value.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return "";
    }

    size_t end = value.find_last_not_of(whitespace);
    return value.substr(start, end - start + 1);
}

std::map<std::string, std::string> loadConfig(const std::string& path) {
    std::map<std::string, std::string> config;

    if (path.empty()) {
        return config;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Failed to open config file: " << path << "\n";
        return config;
    }

    std::string line;

    while (std::getline(file, line)) {
        line = trim(line);

        if (line.empty() || line[0] == '#') {
            continue;
        }

        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }

        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));

        if (!key.empty()) {
            config[key] = value;
        }
    }

    return config;
}

std::string configValue(
    const std::map<std::string, std::string>& config,
    const std::string& key,
    const std::string& defaultValue
) {
    auto it = config.find(key);
    if (it == config.end()) {
        return defaultValue;
    }

    return it->second;
}

std::string getArg(int argc, char** argv, const std::string& name, const std::string& defaultValue) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == name) {
            return argv[i + 1];
        }
    }

    return defaultValue;
}

int getIntArg(int argc, char** argv, const std::string& name, int defaultValue) {
    return std::stoi(getArg(argc, argv, name, std::to_string(defaultValue)));
}

void printUsage() {
    std::cout
        << "Usage:\n"
        << "  Config mode:\n"
        << "    sudo ./asset_collector --config <config-file> [--count <n>]\n\n"
        << "  Live mode:\n"
        << "    sudo ./asset_collector --mode live --iface <interface> [--count <n>] [--filter <filter>]\n\n"
        << "  PCAP mode:\n"
        << "    ./asset_collector --mode pcap --file <pcap-file> [--filter <filter>]\n\n"
        << "Options:\n"
        << "  --config <file>    Load collector settings from config file.\n"
        << "  --url <endpoint>   Default: http://localhost:8000/api/v1/ingest/asset-events\n"
        << "  --count <n>        Stop after n discovered asset events. 0 means unlimited in live mode.\n"
        << "  --duration <sec>   Stop after this many seconds. 0 means no duration limit.\n"
        << "  --batch-size <n>   Number of asset events per HTTP request. Default: 5.\n"
        << "  --parser-workers <n> Number of parser worker threads. Default: 2.\n"
        << "  --filter <value>   Default: arp or DHCP. Use 'all' to disable BPF filter.\n\n"
        << "Examples:\n"
        << "  sudo ./asset_collector --config ../config/collector.conf --count 5\n"
        << "  sudo ./asset_collector --mode live --iface wlp3s0 --count 5\n"
        << "  ./asset_collector --mode pcap --file ../samples/arp-demo.pcap\n";
}

void printSummary(const CollectorStats& stats) {
    std::cout << "\nCollector summary:\n"
              << "- Total packets seen: " << stats.total_packets << "\n"
              << "- Parsed asset events: " << stats.parsed_asset_events << "\n"
              << "- Skipped/unsupported packets: " << stats.skipped_packets << "\n"
              << "- Asset events sent: " << stats.sent_events << "\n"
              << "- Failed sends: " << stats.failed_sends << "\n";
}


class AsyncBatchSender {
public:
    explicit AsyncBatchSender(const std::string& endpoint)
        : client_(endpoint),
          worker_(&AsyncBatchSender::run, this) {}

    ~AsyncBatchSender() {
        stop();
    }

    void enqueue(std::vector<AssetEvent> events) {
        if (events.empty()) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(events));
        }

        cv_.notify_one();
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (stopping_) {
                // stop() may be called manually and again by destructor
            }

            stopping_ = true;
        }

        cv_.notify_one();

        if (worker_.joinable()) {
            worker_.join();
        }
    }

    int sentEvents() const {
        return sent_events_;
    }

    int failedEvents() const {
        return failed_events_;
    }

private:
    void run() {
        while (true) {
            std::vector<AssetEvent> batch;

            {
                std::unique_lock<std::mutex> lock(mutex_);

                cv_.wait(lock, [&]() {
                    return stopping_ || !queue_.empty();
                });

                if (queue_.empty() && stopping_) {
                    break;
                }

                batch = std::move(queue_.front());
                queue_.pop();
            }

            size_t eventCount = batch.size();

            try {
                bool ok = client_.postEvents(batch);

                if (ok) {
                    sent_events_ += static_cast<int>(eventCount);
                    std::cout << "Sender thread posted "
                              << eventCount
                              << " asset event(s)\n";
                } else {
                    failed_events_ += static_cast<int>(eventCount);
                    std::cerr << "Sender thread failed to post "
                              << eventCount
                              << " asset event(s)\n";
                }
            } catch (const std::exception& exc) {
                failed_events_ += static_cast<int>(eventCount);
                std::cerr << "Sender thread exception: "
                          << exc.what()
                          << "\n";
            }
        }
    }

    HttpClient client_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::vector<AssetEvent>> queue_;
    bool stopping_ = false;
    int sent_events_ = 0;
    int failed_events_ = 0;
    std::thread worker_;
};


CollectorStats processPackets(
    pcap_t* handle,
    const std::string& sourceName,
    const std::string& url,
    int countLimit,
    int batchSize,
    int durationSeconds,
    int parserWorkerCount
) {
    struct RawPacket {
        std::vector<uint8_t> data;
        std::string sourceName;
    };

    if (parserWorkerCount <= 0) {
        parserWorkerCount = 1;
    }

    AsyncBatchSender sender(url);

    std::atomic<int> totalPackets{0};
    std::atomic<int> parsedEvents{0};
    std::atomic<int> skippedPackets{0};

    std::queue<RawPacket> rawQueue;
    std::mutex rawQueueMutex;
    std::condition_variable rawQueueCv;
    bool captureFinished = false;

    std::vector<AssetEvent> batch;
    std::mutex batchMutex;
    std::mutex logMutex;

    auto startedAt = std::chrono::steady_clock::now();

    auto durationReached = [&]() {
        if (durationSeconds <= 0) {
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startedAt).count();

        return elapsed >= durationSeconds;
    };

    auto queueBatch = [&](std::vector<AssetEvent> readyBatch) {
        if (readyBatch.empty()) {
            return;
        }

        size_t eventCount = readyBatch.size();
        sender.enqueue(std::move(readyBatch));

        std::lock_guard<std::mutex> lock(logMutex);
        std::cout << "Queued batch with "
                  << eventCount
                  << " asset event(s)\n";
    };

    auto enqueueParsedEvent = [&](AssetEvent event) {
        std::vector<AssetEvent> readyBatch;

        {
            std::lock_guard<std::mutex> lock(batchMutex);
            batch.push_back(std::move(event));

            if (static_cast<int>(batch.size()) >= batchSize) {
                readyBatch = std::move(batch);
                batch.clear();
            }
        }

        queueBatch(std::move(readyBatch));
    };

    auto flushRemainingBatch = [&]() {
        std::vector<AssetEvent> readyBatch;

        {
            std::lock_guard<std::mutex> lock(batchMutex);

            if (!batch.empty()) {
                readyBatch = std::move(batch);
                batch.clear();
            }
        }

        queueBatch(std::move(readyBatch));
    };

    auto parserWorker = [&]() {
        std::vector<std::unique_ptr<ProtocolParser>> parsers;
        parsers.push_back(std::make_unique<ArpParser>());
        parsers.push_back(std::make_unique<DhcpParser>());
        parsers.push_back(std::make_unique<SsdpParser>());

        while (true) {
            RawPacket rawPacket;

            {
                std::unique_lock<std::mutex> lock(rawQueueMutex);

                rawQueueCv.wait(lock, [&]() {
                    return captureFinished || !rawQueue.empty();
                });

                if (rawQueue.empty() && captureFinished) {
                    break;
                }

                rawPacket = std::move(rawQueue.front());
                rawQueue.pop();
            }

            std::optional<AssetEvent> event;

            for (const auto& parser : parsers) {
                event = parser->parse(
                    rawPacket.data.data(),
                    static_cast<int>(rawPacket.data.size()),
                    rawPacket.sourceName
                );

                if (event.has_value()) {
                    break;
                }
            }

            if (!event.has_value()) {
                skippedPackets++;
                continue;
            }

            parsedEvents++;

            {
                std::lock_guard<std::mutex> lock(logMutex);

                std::cout << "Discovered asset ip=" << event->ip
                          << " mac=" << event->mac
                          << " source=" << event->source;

                if (!event->hostname.empty()) {
                    std::cout << " hostname=" << event->hostname;
                }

                std::cout << "\n";
            }

            enqueueParsedEvent(std::move(event.value()));
        }
    };

    std::vector<std::thread> parserWorkers;

    for (int i = 0; i < parserWorkerCount; ++i) {
        parserWorkers.emplace_back(parserWorker);
    }

    while (running) {
        if (durationReached()) {
            break;
        }

        if (countLimit > 0 && parsedEvents.load() >= countLimit) {
            break;
        }

        struct pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;

        int result = pcap_next_ex(handle, &header, &packet);

        if (result == 0) {
            continue;
        }

        if (result == -1) {
            std::cerr << "pcap error: " << pcap_geterr(handle) << "\n";
            break;
        }

        if (result == -2) {
            break;
        }

        RawPacket rawPacket;
        rawPacket.sourceName = sourceName;
        rawPacket.data.assign(packet, packet + header->caplen);

        {
            std::lock_guard<std::mutex> lock(rawQueueMutex);
            rawQueue.push(std::move(rawPacket));
        }

        rawQueueCv.notify_one();
        totalPackets++;
    }

    {
        std::lock_guard<std::mutex> lock(rawQueueMutex);
        captureFinished = true;
    }

    rawQueueCv.notify_all();

    for (auto& worker : parserWorkers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    flushRemainingBatch();

    sender.stop();

    CollectorStats stats;
    stats.total_packets = totalPackets.load();
    stats.parsed_asset_events = parsedEvents.load();
    stats.skipped_packets = skippedPackets.load();
    stats.sent_events = sender.sentEvents();
    stats.failed_sends = sender.failedEvents();

    return stats;
}

int main(int argc, char** argv) {
    std::string configPath = getArg(argc, argv, "--config", "");
    auto config = loadConfig(configPath);

    if (!configPath.empty()) {
        std::cout << "Loaded config: " << configPath << "\n";
    }

    std::string defaultFilter = "arp or (udp and (port 67 or port 68)) or udp port 1900";

    std::string mode = getArg(argc, argv, "--mode", configValue(config, "mode", "live"));
    std::string iface = getArg(argc, argv, "--iface", configValue(config, "interface", ""));
    std::string file = getArg(argc, argv, "--file", configValue(config, "file", ""));
    std::string url = getArg(argc, argv, "--url", configValue(config, "url", "http://localhost:8000/api/v1/ingest/asset-events"));
    std::string captureFilter = getArg(argc, argv, "--filter", configValue(config, "filter", defaultFilter));

    int configuredCount = 0;
    try {
        configuredCount = std::stoi(configValue(config, "count", "0"));
    } catch (...) {
        configuredCount = 0;
    }

    int configuredBatchSize = 5;
    try {
        configuredBatchSize = std::stoi(configValue(config, "batch_size", "5"));
    } catch (...) {
        configuredBatchSize = 5;
    }

    int configuredDuration = 0;
    try {
        configuredDuration = std::stoi(configValue(config, "duration", "0"));
    } catch (...) {
        configuredDuration = 0;
    }

    int configuredParserWorkers = 2;
    try {
        configuredParserWorkers = std::stoi(configValue(config, "parser_workers", "2"));
    } catch (...) {
        configuredParserWorkers = 2;
    }

    int countLimit = getIntArg(argc, argv, "--count", configuredCount);
    int batchSize = getIntArg(argc, argv, "--batch-size", configuredBatchSize);
    int durationSeconds = getIntArg(argc, argv, "--duration", configuredDuration);
    int parserWorkerCount = getIntArg(argc, argv, "--parser-workers", configuredParserWorkers);

    if (batchSize <= 0) {
        batchSize = 1;
    }

    if (parserWorkerCount <= 0) {
        parserWorkerCount = 1;
    }

    std::signal(SIGINT, handleSignal);

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = nullptr;
    std::string sourceName;

    if (mode == "live") {
        if (iface.empty()) {
            printUsage();
            return 1;
        }

        handle = pcap_open_live(
            iface.c_str(),
            65535,
            1,
            1000,
            errbuf
        );

        if (!handle) {
            std::cerr << "Failed to open interface " << iface << ": " << errbuf << "\n";
            return 1;
        }

        sourceName = iface;
        std::cout << "Mode: live\n";
        std::cout << "Listening on interface: " << iface << "\n";
    } else if (mode == "pcap") {
        if (file.empty()) {
            printUsage();
            return 1;
        }

        handle = pcap_open_offline(file.c_str(), errbuf);

        if (!handle) {
            std::cerr << "Failed to open pcap file " << file << ": " << errbuf << "\n";
            return 1;
        }

        sourceName = file;
        std::cout << "Mode: pcap\n";
        std::cout << "Reading packets from file: " << file << "\n";
    } else {
        printUsage();
        return 1;
    }

    int datalink = pcap_datalink(handle);

    if (datalink != DLT_EN10MB) {
        const char* linkName = pcap_datalink_val_to_name(datalink);
        std::cerr << "Unsupported datalink type: "
                  << (linkName ? linkName : "unknown")
                  << " (" << datalink << "). Only Ethernet is supported in this MVP.\n";
        pcap_close(handle);
        return 1;
    }

    struct bpf_program fp;
    bool filterInstalled = false;

    if (captureFilter != "all") {
        if (pcap_compile(handle, &fp, captureFilter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Failed to compile filter: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return 1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Failed to set filter: " << pcap_geterr(handle) << "\n";
            pcap_freecode(&fp);
            pcap_close(handle);
            return 1;
        }

        filterInstalled = true;
        std::cout << "Capture filter: " << captureFilter << "\n";
    } else {
        std::cout << "Capture filter: all packets\n";
    }

    std::cout << "Posting events to " << url << "\n";

    if (countLimit == 0) {
        std::cout << "Run mode: continuous\n";
    } else {
        std::cout << "Run mode: stop after " << countLimit << " asset event(s)\n";
    }

    if (durationSeconds > 0) {
        std::cout << "Duration limit: " << durationSeconds << " second(s)\n";
    }

    std::cout << "Batch size: " << batchSize << "\n";
    std::cout << "Parser workers: " << parserWorkerCount << "\n";

    CollectorStats stats = processPackets(
        handle,
        sourceName,
        url,
        countLimit,
        batchSize,
        durationSeconds,
        parserWorkerCount
    );

    if (filterInstalled) {
        pcap_freecode(&fp);
    }

    pcap_close(handle);

    printSummary(stats);

    return 0;
}
