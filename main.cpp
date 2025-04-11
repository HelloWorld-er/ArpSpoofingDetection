//
// Created by Yimin Liu on 10/4/2025.
//
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <memory>
#include <cstdio>
#include <string>
#include <array>
#include <unordered_set>
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
#include <cstdlib>
PlatformID platform_id = PlatformID::MACOS;
#elif defined(__linux__)
PlatformID platform_id = PlatformID::LINUX;
#else
PlatformID platform_id = PlatformID::UNKNOWN;
#endif

class ActivePrivateNetworkIP {
public:
    std::string ip_address;
    std::time_t last_seen_time;
    bool is_router = false;
    ActivePrivateNetworkIP(std::string ip_addr, std::time_t last_seen, bool if_router = false) {
        ip_address = std::move(ip_addr);
        last_seen_time = last_seen;
        is_router = if_router;
    }
    void refresh_last_time(std::time_t new_last_seen) {
        last_seen_time = new_last_seen;
    }
    std::time_t calc_time_pass(const std::time_t& new_last_seen) const {
        return new_last_seen - last_seen_time;
    }
    bool ip_equals_to(const std::string& ip_addr) const {
        return ip_address == ip_addr;
    }
    bool if_router() const {
        return is_router == true;
    }
};

std::unordered_set<std::string> get_router_ips(const std::string&);
int get_dhcp_lease_time(const std::string&);
bool check(int, int, const char*, pcap_t*);
std::string bytes_to_hex(const u_char*, size_t, const char*);
std::string bytes_to_int(const u_char*, size_t, const char*);

std::unordered_map<std::string, ActivePrivateNetworkIP> mac_to_ip_map;
const std::string unknown_mac_address = "00:00:00:00:00:00";
std::unordered_set<std::string> router_ip_addrs;
int dhcp_lease_time;

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

    std::string interface = "en0";

    pcap_t *pcap_handle = pcap_create(interface.c_str(), error_buf);
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

    // get routers' ips
    router_ip_addrs = get_router_ips(interface);

    // get DHCP lease time
    dhcp_lease_time = get_dhcp_lease_time(interface);
    if (dhcp_lease_time < 0) {
        pcap_close(pcap_handle);
        return 1;
    }
    std::cout << "dhcp_lease_time: " << dhcp_lease_time << std::endl;

    std::cout << "capturing: " << std::endl;

    pcap_loop(pcap_handle, 0, [](u_char *args, const pcap_pkthdr *header, const u_char *packet) -> void {
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

        std::time_t current_time = std::time(nullptr);
        // check sender mac-ip pair
        if (mac_to_ip_map.find(sender_mac) == mac_to_ip_map.end()) {
            if (router_ip_addrs.find(sender_mac) == router_ip_addrs.end()) {
                mac_to_ip_map.insert({sender_mac, ActivePrivateNetworkIP(sender_ip, current_time)});
            }
            else {
                mac_to_ip_map.insert({sender_mac, ActivePrivateNetworkIP(sender_ip, current_time, true)});
            }
        }
        else {
            auto& entry = mac_to_ip_map.at(sender_mac);
            if (!entry.ip_equals_to(sender_ip)) {
                if (entry.if_router() || entry.calc_time_pass(current_time) < dhcp_lease_time) {
                    std::cerr << "[STRONG WARNING] "<< sender_mac << " doesn't match sender IP " << sender_ip << std::endl;
                    std::cerr << "Suspicious IP address: " << sender_ip << std::endl;
                }
                else {
                    std::cerr << "[WEAK WARNING] It seems that " << sender_mac << " allocates to another ip address " << sender_ip << " from the previous ip address " << entry.ip_address << std::endl;
                    entry.ip_address = sender_ip;
                    entry.refresh_last_time(current_time);
                }
            }
            else {
                entry.refresh_last_time(current_time);
            }
        }

        // check target mac-ip pair
        if (target_mac != unknown_mac_address) {
            if (mac_to_ip_map.find(target_mac) == mac_to_ip_map.end()) {
                mac_to_ip_map.insert({target_mac, ActivePrivateNetworkIP(target_ip, current_time)});
            }
            else {
                auto& entry = mac_to_ip_map.at(target_mac);
                if (!entry.ip_equals_to(target_ip)) {
                    if (entry.if_router() || entry.calc_time_pass(current_time < dhcp_lease_time)) {
                        std::cerr << "[STRONG WARNING] "<< target_mac << " doesn't match sender IP " << target_ip << std::endl;
                        std::cerr << "Suspicious IP address: " << target_ip << std::endl;
                    }
                    else {
                        std::cerr << "[WEAK WARNING] It seems that " << target_mac << " allocates to another ip address " << target_ip << " from the previous ip address " << entry.ip_address << std::endl;
                        entry.ip_address = target_ip;
                        entry.refresh_last_time(current_time);
                    }
                }
                else if (target_mac != unknown_mac_address) {
                    entry.refresh_last_time(current_time);
                }
            }
        }

    }, nullptr);

    pcap_close(pcap_handle);
    return 0;
}

uint64_t hex_to_uint64(const std::string &hex) {
    uint64_t hex_uint64;
    std::stringstream uint64_stream;
    uint64_stream << std::hex << hex;
    uint64_stream >> hex_uint64;
    return hex_uint64;
}

uint32_t hex_to_uint32(const std::string &hex) {
    uint32_t hex_uint32;
    std::stringstream uint32_stream;
    uint32_stream << std::hex << hex;
    uint32_stream >> hex_uint32;
    return hex_uint32;
}

uint16_t hex_to_uint16(const std::string &hex) {
    uint16_t hex_uint16;
    std::stringstream uint16_stream;
    uint16_stream << std::hex << hex;
    uint16_stream >> hex_uint16;
    return hex_uint16;
}

uint8_t hex_to_uint8(const std::string &hex) {
    uint8_t hex_uint8;
    std::stringstream uint8_stream;
    uint8_stream << std::hex << hex;
    uint8_stream >> hex_uint8;
    return hex_uint8;
}

std::vector<std::string> split(const std::string &s, std::string delims) {
    std::vector<std::string> returned_vector;
    std::istringstream split_stream(s);
    std::string sub_string;
    std::unordered_set<char> delim_set (delims.begin(), delims.end());
    char current_char;
    while (split_stream.get(current_char)) {
        if (delim_set.find(current_char) == delim_set.end()) {
            sub_string += current_char;
        }
        else {
            if (!sub_string.empty()) {
                returned_vector.push_back(sub_string);
                sub_string.clear();
            }
        }
    }
    if (!sub_string.empty()) returned_vector.push_back(sub_string);
    return returned_vector;
}


std::unordered_set<std::string> get_router_ips(const std::string& interface) {
    if (platform_id == PlatformID::WINDOWS) {
    }
    else if (platform_id == PlatformID::MACOS) {
        std::array<char, 128> buffer;
        std::string command_output_string;
        std::string command = "ipconfig getpacket " + interface + " | grep router";
        std::cout << "running command: " << command << std::endl;
        std::unique_ptr<FILE, decltype(&pclose)> stream(popen(command.c_str(), "r"), pclose);
        if (stream == nullptr) { // equivalent to stream.get() == nullptr
            std::cerr << "popen() failed" << std::endl;
            return std::unordered_set<std::string>(0);
        }
        while (fgets(buffer.data(), buffer.size(), stream.get()) != nullptr) {
            command_output_string += buffer.data();
        }

        command_output_string.erase(command_output_string.find_last_not_of("\r\n") + 1);
        std::cout << command_output_string << std::endl;

        // extract
        std::unordered_set<std::string> router_ips;
        std::string routers;
        std::string router_ip;
        size_t routers_start_idx = command_output_string.find('{');
        size_t routers_end_idx = command_output_string.find('}');
        if (routers_start_idx != std::string::npos && routers_end_idx != std::string::npos) {
            if (routers_start_idx + 1 == routers_end_idx) {
                std::cerr << "NO routers found!" << std::endl;
                return std::unordered_set<std::string>(0);
            }
            routers = command_output_string.substr(routers_start_idx + 1, routers_end_idx - routers_start_idx - 1);
            std::istringstream ip_stream(routers);
            while (std::getline(ip_stream, router_ip, ',')) {
                router_ip.erase(0, router_ip.find_first_not_of(" \t"));
                router_ip.erase(router_ip.find_last_not_of(" \t") + 1);
                if (!router_ip.empty()) {
                    router_ips.insert(router_ip);
                }
                else break;
            }
            for (auto& router_ip_addr : router_ips) {
                std::cout << router_ip_addr << " ";
            }
            std::cout << std::endl;
            return router_ips;
        }
        std::cerr << "NO routers found!" << std::endl;
        return std::unordered_set<std::string>(0);

    }
    else if (platform_id == PlatformID::LINUX) {}
    else {

    }
    return std::unordered_set<std::string>(0);
}

int get_dhcp_lease_time(const std::string& interface) {
    if (platform_id == PlatformID::WINDOWS) {
        std::array<char, 128> buffer;
        std::string command_output_string;
        std::string command = R"(ipconfig /all | findstr /C:"DHCP Enabled" /C:"Lease Obtained" /C:"Lease Expires")";
        std::cout << "running command: " << command << std::endl;
        std::unique_ptr<FILE, decltype(&pclose)> stream(popen(command.c_str(), "r"), pclose);
        if (stream == nullptr) {
            std::cerr << "popen() failed!" << std::endl;
            return -1;
        }
        while (fgets(buffer.data(), buffer.size(), stream.get()) != nullptr) {
            command_output_string += buffer.data();
        }

        command_output_string.erase(command_output_string.find_last_not_of("\r\n") + 1);
        std::cout << command_output_string << std::endl;

        // extract
        std::string DHCP_state_str;
        std::string lease_obtained;
        std::string lease_expires;
        std::string output_line;
        int idx = 0;
        std::istringstream DHCP_lease_time_stream(command_output_string);
        while (std::getline(DHCP_lease_time_stream, output_line)) {
            switch (idx) {
                case 0: DHCP_state_str = output_line.substr(output_line.find(':') + 1); DHCP_state_str.erase(0, DHCP_state_str.find_first_not_of(" \t")); DHCP_state_str.erase(DHCP_state_str.find_last_not_of(" \t\n\r") + 1); break;
                case 1: lease_obtained = output_line.substr(output_line.find(':') + 1); lease_obtained.erase(0, lease_obtained.find_first_not_of(" \t")); lease_obtained.erase(lease_obtained.find_last_not_of(" \t\n\r") + 1); break;
                case 2: lease_expires = output_line.substr(output_line.find(':') + 1);  lease_expires.erase(0, lease_expires.find_first_not_of(" \t")); lease_expires.erase(lease_expires.find_last_not_of(" \t\n\r") + 1);break;
                default: break;
            }
            idx ++;
        }
        std::cout << DHCP_state_str << std::endl;
        std::cout << lease_obtained << std::endl;
        std::cout << lease_expires << std::endl;
        if (DHCP_state_str.empty() || lease_obtained.empty() || lease_expires.empty() || DHCP_state_str == "No") {
            std::cerr << "DHCP lease time not found" << std::endl;
            return -1;
        }

        std::unordered_map<std::string, int> months = {
            {"January", 1},
            {"February", 2},
            {"March", 3},
            {"April", 4},
            {"May", 5},
            {"June", 6},
            {"July", 7},
            {"August", 8},
            {"September", 9},
            {"October", 10},
            {"November", 11},
            {"December", 12}
        };

        std::tm start_time_info = {}, end_time_info = {};
        // day, mday mon year h:m:s am/pm
        std::vector<std::string> start_time_data_vector = split(lease_obtained, " ,:");

        start_time_info.tm_mday = std::stoi(start_time_data_vector[1]);
        start_time_info.tm_mon = months[start_time_data_vector[2]];
        start_time_info.tm_year = std::stoi(start_time_data_vector[3]);
        start_time_info.tm_hour = std::stoi(start_time_data_vector[4]);
        start_time_info.tm_min = std::stoi(start_time_data_vector[5]);
        start_time_info.tm_sec = std::stoi(start_time_data_vector[6]);
        if (start_time_data_vector[7] == "pm") start_time_info.tm_hour += 12;
        std::time_t start_t = std::mktime(&start_time_info);

        std::vector<std::string> end_time_data_vector = split(lease_expires, " ,:");

        end_time_info.tm_mday = std::stoi(end_time_data_vector[1]);
        end_time_info.tm_mon = months[end_time_data_vector[2]];
        end_time_info.tm_year = std::stoi(end_time_data_vector[3]);
        end_time_info.tm_hour = std::stoi(end_time_data_vector[4]);
        end_time_info.tm_min = std::stoi(end_time_data_vector[5]);
        end_time_info.tm_sec = std::stoi(end_time_data_vector[6]);
        if (end_time_data_vector[7] == "pm") end_time_info.tm_hour += 12;
        std::time_t end_t = std::mktime(&end_time_info);

        if (start_t < 0 || end_t < 0) {
            std::cerr << "unrecognizable time" << std::endl;
            return -1;
        }

        return static_cast<int>(end_t - start_t);
    }
    if (platform_id == PlatformID::MACOS) {
        std::array<char, 128> buffer;
        std::string command_output_string;
        std::string command = "ipconfig getpacket " + interface + " | grep lease_time";
        std::cout << "running command: " << command << std::endl;
        std::unique_ptr<FILE, decltype(&pclose)> stream(popen(command.c_str(), "r"), pclose);
        if (stream == nullptr) { // equivalent to stream.get() == nullptr
            std::cerr << "popen() failed" << std::endl;
            return -1;
        }
        while (fgets(buffer.data(), buffer.size(), stream.get()) != nullptr) {
            command_output_string += buffer.data();
        }

        command_output_string.erase(command_output_string.find_last_not_of('\n') + 1);
        std::cout << command_output_string << std::endl;

        // extract data_type = uint32 and value in string
        std::string data_type;
        std::string value;
        size_t type_start_idx = command_output_string.find('(');
        size_t type_end_idx = command_output_string.find(')');
        size_t value_start_idx = command_output_string.find(':');
        if (type_start_idx != std::string::npos && type_end_idx != std::string::npos && value_start_idx != std::string::npos) {
            data_type = command_output_string.substr(type_start_idx + 1, type_end_idx - type_start_idx - 1);
            value = command_output_string.substr(value_start_idx + 1);
            data_type.erase(0, data_type.find_first_not_of(" \t"));
            data_type.erase(data_type.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
        }
        else {
            std::cerr << "cannot identify dhcp lease time" << std::endl;
            return -1;
        }

        // convert value in string to value in corresponding data_type
        if (data_type == "uint64") return hex_to_uint64(value);
        if (data_type == "uint32") return hex_to_uint32(value);
        if (data_type == "uint16") return hex_to_uint16(value);
        if (data_type == "uint8") return hex_to_uint8(value);
        std::cerr << "unknown dhcp lease time type (e.g. uint32)" << std::endl;
        return -1;
    }
    if (platform_id == PlatformID::LINUX) {

    }
    else {
        // implicitly means that platform_id = PlatformID::UNKNOWN;
    }
    return -1;
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
