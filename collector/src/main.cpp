#include <pcap.h>

#include <csignal>
#include <iostream>
#include <string>

#include "ArpParser.hpp"
#include "HttpClient.hpp"

static bool running = true;

void handleSignal(int) {
    running = false;
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
        << "  Live mode:\n"
        << "    sudo ./asset_collector --mode live --iface <interface> [--count <n>]\n\n"
        << "  PCAP mode:\n"
        << "    ./asset_collector --mode pcap --file <pcap-file>\n\n"
        << "Options:\n"
        << "  --url <endpoint>   Default: http://localhost:8000/api/v1/ingest/asset-events\n"
        << "  --count <n>        Stop after n discovered asset events. 0 means unlimited in live mode.\n\n"
        << "Examples:\n"
        << "  sudo ./asset_collector --mode live --iface wlp3s0 --count 5\n"
        << "  ./asset_collector --mode pcap --file ../samples/arp-demo.pcap\n";
}

int processPackets(
    pcap_t* handle,
    const std::string& iface,
    const std::string& url,
    int countLimit
) {
    ArpParser parser;
    HttpClient client(url);

    int captured = 0;

    while (running) {
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

        auto event = parser.parse(packet, header->caplen, iface);
        if (!event.has_value()) {
            continue;
        }

        std::cout << "Discovered asset ip=" << event->ip
                  << " mac=" << event->mac
                  << " source=" << event->source << "\n";

        client.postEvents({event.value()});

        captured++;

        if (countLimit > 0 && captured >= countLimit) {
            break;
        }
    }

    return captured;
}

int main(int argc, char** argv) {
    std::string mode = getArg(argc, argv, "--mode", "live");
    std::string iface = getArg(argc, argv, "--iface", "");
    std::string file = getArg(argc, argv, "--file", "");
    std::string url = getArg(argc, argv, "--url", "http://localhost:8000/api/v1/ingest/asset-events");
    int countLimit = getIntArg(argc, argv, "--count", 0);

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
        std::cout << "Listening for ARP packets on interface " << iface << "\n";
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
        std::cout << "Reading ARP packets from pcap file " << file << "\n";
    } else {
        printUsage();
        return 1;
    }

    struct bpf_program fp;
    const char* filter = "arp";

    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
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

    std::cout << "Posting events to " << url << "\n";

    int captured = processPackets(handle, sourceName, url, countLimit);

    pcap_freecode(&fp);
    pcap_close(handle);

    std::cout << "Collector stopped. Captured asset events: " << captured << "\n";

    return 0;
}
