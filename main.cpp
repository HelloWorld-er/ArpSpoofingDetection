//
// Created by Yimin Liu on 10/4/2025.
//
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include <netinet/if_ether.h>

enum class PlatformID {
    WINDOWS,
    MACOS,
    LINUX,
    UNKNOWN
};
std::ostream& operator<<(std::ostream& os, PlatformID platform_id) {
    switch (platform_id) {
        case PlatformID::WINDOWS: os << "Windows"; break;
        case PlatformID::MACOS: os << "Macos"; break;
        case PlatformID::LINUX: os << "Linux"; break;
        case PlatformID::UNKNOWN: os << "Unknown"; break;
    }
    return os;
}

#if defined(_WIN32) || defined(_WIN64)
PlatformID platform_id = PlatformID::WINDOWS;
#elif defined(__APPLE__) || defined(__MACH__)
PlatformID platform_id = PlatformID::MACOS;
#elif defined(__linux__)
PlatformID platform_id = PlatformID::LINUX;
#else
PlatformID platform_id = PlatformID::UNKNOWN;
#endif

int get_dhcp_lease_time();
bool check(int, int, const char*, pcap_t*);
std::string bytes_to_hex(const u_char*, size_t, const char*);
std::string bytes_to_int(const u_char*, size_t, const char*);

std::unordered_map<std::string, std::string> mac_to_ip_map;
const std::string unknown_mac_address = "00:00:00:00:00:00";

int main() {
    std::cout << "Platform: " << platform_id << std::endl;

    char error_buf[PCAP_ERRBUF_SIZE];
    int signal;
    signal = pcap_init(PCAP_CHAR_ENC_LOCAL, error_buf);
    if (signal == PCAP_ERROR) {
        std::cerr << error_buf << std:: endl;
        return 1;
    }
    std::cout << "is_init: Success" << std::endl;

    pcap_if_t *head_dev_pointer, *current_dev_pointer;
    signal = pcap_findalldevs(&head_dev_pointer, error_buf);
    if (signal == PCAP_ERROR) {
        std::cerr << error_buf << std:: endl;
        return 1;
    }

    bool flag = false;
    current_dev_pointer = head_dev_pointer;
    while (current_dev_pointer != nullptr) {
        if (std::string(current_dev_pointer->name) == "en0") {
            flag = true;
            break;
        }
        std::cout << "current dev: " << current_dev_pointer->name << std::endl;
        current_dev_pointer = current_dev_pointer -> next;
    }
    pcap_freealldevs(head_dev_pointer);

    if (!flag) {
        std::cout << flag << std::endl;
        std::cerr << "No en0 found" << std::endl;
        return 1;
    }

    pcap_t *pcap_handle = pcap_create("en0", error_buf);
    if (pcap_handle == nullptr) {
        std::cerr << error_buf << std::endl;
        pcap_close(pcap_handle);
        return 1;
    }
    std::cout << "pcap_create: " << pcap_handle << std::endl;

    pcap_set_snaplen(pcap_handle, 65535);
    pcap_set_promisc(pcap_handle, 1); // promiscuous mode should be set on the capture handle when the handle is activated
    pcap_set_immediate_mode(pcap_handle, 1);

    int activation_status = pcap_activate(pcap_handle);
    if (!check(activation_status, 0, "Activation: ", pcap_handle)) {
        pcap_close(pcap_handle);
        return 1;
    }

    signal = pcap_datalink(pcap_handle);
    if (!check(signal, DLT_EN10MB, "Datalink: ", pcap_handle)) {
        pcap_close(pcap_handle);
        return 1;
    }

    auto *filter_pointer = new bpf_program();
    signal = pcap_compile(pcap_handle, filter_pointer, "arp", 1, PCAP_NETMASK_UNKNOWN);
    if (!check(signal, 0, "pcap compile filter: ", pcap_handle)) {
        pcap_close(pcap_handle);
        return 1;
    }
    signal = pcap_setfilter(pcap_handle, filter_pointer);
    pcap_freecode(filter_pointer);
    delete filter_pointer;
    if (!check(signal, 0, "pcap set filter: ", pcap_handle)) {
        pcap_close(pcap_handle);
        return 1;
    }

    // get DHCP lease time
    int dhcp_lease_time = get_dhcp_lease_time();

    std::cout << "capturing: " << std::endl;

    pcap_loop(pcap_handle, 10, [](u_char *args, const pcap_pkthdr *header, const u_char *packet) -> void {
        // packet
        // ethernet header + payload (in this case, arp header)
        std::cout << "Packet captured: Length = " << header->len << std::endl;

        const auto *packet_header = reinterpret_cast<const ether_header *>(packet);
        if (ntohs(packet_header->ether_type) != ETHERTYPE_ARP) return;

        const auto *arp_header = reinterpret_cast<const ether_arp *>(packet + sizeof(ether_header)); // move the pointer to the arp header

        std::string sender_mac = bytes_to_hex(arp_header->arp_sha, ETHER_ADDR_LEN, ":");
        std::string sender_ip = bytes_to_int(arp_header->arp_spa, 4, ".");
        std::string target_mac = bytes_to_hex(arp_header->arp_tha, ETHER_ADDR_LEN, ":");
        std::string target_ip = bytes_to_int(arp_header->arp_tpa, 4, ".");

        std::cout << "ARP sender MAC address: " << sender_mac << std::endl;
        std::cout << "ARP sender Protocol address (IP): " << sender_ip << std::endl;
        std::cout << "ARP target MAC address: " << target_mac << std::endl;
        std::cout << "ARP target Protocol address (IP): " << target_ip << std::endl;
        std::cout << std::endl;

        if (mac_to_ip_map.find(sender_mac) == mac_to_ip_map.end()) {
            mac_to_ip_map.insert({sender_mac, sender_ip});
        }
        else if (mac_to_ip_map[sender_mac] != sender_ip) {
            std::cerr << "[WARNING] "<< sender_mac << " doesn't match sender IP " << sender_ip << std::endl;
            std::cerr << "Suspicious IP address: " << sender_ip << std::endl;
            // pcap_breakloop(reinterpret_cast<pcap_t *>(args));
        }

        if (mac_to_ip_map.find(target_mac) == mac_to_ip_map.end()) {
            mac_to_ip_map.insert({target_mac, target_ip});
        }
        else if (target_mac != unknown_mac_address && mac_to_ip_map[target_mac] != target_ip) {
            std::cerr << "[WARNING] " << target_mac << " doesn't match target IP " << target_ip << std::endl;
            // pcap_breakloop(reinterpret_cast<pcap_t *>(args));
        }

    }, reinterpret_cast<u_char *>(pcap_handle));

    pcap_close(pcap_handle);
    return 0;
}


std::string bytes_to_int(const u_char *bytes, size_t len, const char* seperator = "") {
    std::string bytes_in_int;
    for (size_t i = 0; i < len; i ++) {
        bytes_in_int += std::to_string(bytes[i]);
        if (i < len - 1) bytes_in_int += seperator;
    }
    return bytes_in_int;
}

std::string bytes_to_hex(const u_char *bytes, size_t len, const char* seperator = "") {
    std::ostringstream hex_stream;
    for (size_t i = 0; i < len; i ++) {
        hex_stream <<  std::hex << std::setfill('0') << std::setw(2) << static_cast<const int>(bytes[i]);
        if (i < len - 1) hex_stream << seperator;
    }
    return hex_stream.str();
}

bool check(int signal, int target, const char* prefix, pcap_t* pcap_handle) {
    if (signal == target) {
        std::cout << prefix << "Success" << std::endl;
        return true;
    }
    pcap_perror(pcap_handle, "prefix");
    return false;
}
