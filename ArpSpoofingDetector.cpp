//
// Created by Yimin Liu on 14/4/2025.
//

#include "ArpSpoofingDetector.h"
#include <iostream>
#include <stdexcept> // error handling
#include <iomanip> // formated output
#include <ctime> // struct tm, typedef time_t
#include <memory> // for unique_ptr
#include <cstdio> // pipe: FILE fclose()
#include <array> // std::array
#include <unordered_map> // std::unordered_map
#include <sstream> // stringstream
#include <cstdint> // for uint32 uint16 ...


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

template <typename Detector>
ArpSpoofingDetect::PacketCapturer<Detector>::PacketCapturer() {
}

template <typename Detector>
ArpSpoofingDetect::PacketCapturer<Detector>::~PacketCapturer() {
    if (m_pcap_handle != nullptr) {
        pcap_close(m_pcap_handle);
    }
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetMessageHandleFn(void(Detector::*message_handle_fn)(const std::string& new_message, const bool& raise_error, bool end_line), Detector* detector) {
    AddMessage = [message_handle_fn, detector](const std::string& new_message, const bool& raise_error, bool end_line = true) {
        (detector->*message_handle_fn)(new_message, raise_error, end_line);
    };
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::InitCapturer() {
    const int signal = pcap_init(PCAP_CHAR_ENC_LOCAL, m_error_buf);
    if (signal == PCAP_ERROR) {
        AddMessage("[ERROR] " + std::string(m_error_buf), true, true);
    }
}

template <typename Detector>
bool ArpSpoofingDetect::PacketCapturer<Detector>::CheckGeneralSignal(int signal, int success_signal, const std::string &prefix, pcap_t *pcap_handle) const {
    if (signal == success_signal) {
        AddMessage(prefix + "Success", false, true);
        return true;
    }
    AddMessage(prefix + std::string(pcap_geterr(pcap_handle)), false, true);
    return false;
}

template <typename Detector>
bool ArpSpoofingDetect::PacketCapturer<Detector>::IfPcapDevDescExist(pcap_if_t device) {
    return device.description != nullptr;
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::CheckAvailableDevices() {
    pcap_if_t *head_dev_pointer;
    const int signal = pcap_findalldevs(&head_dev_pointer, m_error_buf);
    if (signal == PCAP_ERROR) {
        AddMessage("[ERROR] " + std::string(m_error_buf), true, true);
        return;
    }

    int count = 1;
    const pcap_if_t *current_dev_pointer = head_dev_pointer;
    while (current_dev_pointer != nullptr) {
        AddMessage("device " + std::to_string(count) + ": " + std::string(current_dev_pointer->name), false, true);
        if (IfPcapDevDescExist(*current_dev_pointer)) AddMessage("description: " + std::string(current_dev_pointer->description), false, true);
        current_dev_pointer = current_dev_pointer -> next;
        count ++;
    }
    pcap_freealldevs(head_dev_pointer);
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::GetDevice() {

    pcap_if_t *head_dev_pointer;
    const int signal = pcap_findalldevs(&head_dev_pointer, m_error_buf);
    if (signal == PCAP_ERROR) {
        AddMessage("[ERROR] " + std::string(m_error_buf), true, true);
        return;
    }

    bool flag = false;
    pcap_if_t *current_dev_pointer = head_dev_pointer;
    while (current_dev_pointer != nullptr) {
        AddMessage("current dev: " + std::string(current_dev_pointer->name), false, true);
        if (IfPcapDevDescExist(*current_dev_pointer)) AddMessage("description: " + std::string(current_dev_pointer->description), false, true);
#if defined(_WIN32) || defined(_WIN64)
        if (IfPcapDevDescExist(*current_dev_pointer) && std::string(current_dev_pointer->description).find(m_target_device_keyword) != std::string::npos) {
            device = current_dev_pointer->name;
            flag = true;
            break;
        }
#elif defined(__APPLE__) || defined(__MACH__)
        if (m_target_device_keyword.empty() || m_target_device_keyword == "any" || std::string(current_dev_pointer->name) == m_target_device_keyword) {
            m_device = current_dev_pointer->name;
            flag = true;
            break;
        }
#endif
        current_dev_pointer = current_dev_pointer -> next;
    }
    pcap_freealldevs(head_dev_pointer);

    if (!flag) {
        AddMessage("[ERROR] No device match with: " + m_target_device_keyword, true, true);
        return;
    }
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::InitPcapHandle() {
    m_pcap_handle = pcap_create(m_device.c_str(), m_error_buf);
    if (m_pcap_handle == nullptr) {
        pcap_close(m_pcap_handle);
        AddMessage("[ERROR] " + std::string(m_error_buf), true, true);
        return;
    }
    AddMessage("pcap_create: Successful", false, true);

    pcap_set_snaplen(m_pcap_handle, m_snaplen);
    pcap_set_promisc(m_pcap_handle, m_promisc_mode); // promiscuous mode should be set on the capture handle when the handle is activated
    pcap_set_immediate_mode(m_pcap_handle, m_immediate_mode);
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::ActivateCapturer() {
    if (m_pcap_handle == nullptr) AddMessage("[ERROR] pcap handle is not initialized, cannot activate", true, true);
    int activation_status = pcap_activate(m_pcap_handle);
    if (!CheckGeneralSignal(activation_status, 0, "Activation: ", m_pcap_handle)) {
        pcap_close(m_pcap_handle);
        AddMessage("[ERROR] Activation Failed", true, true);
        return;
    }
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::CheckDatalink() {
    int signal = pcap_datalink(m_pcap_handle);
    if (!CheckGeneralSignal(signal, m_datalink, "Datalink: ", m_pcap_handle)) {
        pcap_close(m_pcap_handle);
        AddMessage("[ERROR] Datalink Failed", true, true);
        return;
    }
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetupFilter() {
    auto *filter_pointer = new bpf_program();
    int signal = pcap_compile(m_pcap_handle, filter_pointer, m_filter_expression.c_str(), 1, PCAP_NETMASK_UNKNOWN);
    if (!CheckGeneralSignal(signal, 0, "pcap compile filter: ", m_pcap_handle)) {
        pcap_close(m_pcap_handle);
        AddMessage("[ERROR] Filter Expression Compilation Failed", true, true);
        return;
    }
    signal = pcap_setfilter(m_pcap_handle, filter_pointer);
    pcap_freecode(filter_pointer);
    delete filter_pointer;

    if (!CheckGeneralSignal(signal, 0, "pcap set filter: ", m_pcap_handle)) {
        pcap_close(m_pcap_handle);
        AddMessage("[ERROR] Set Filter Failed", true, true);
        return;
    }
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetupCapturer() {
    InitCapturer();
    GetDevice();
    InitPcapHandle();
    ActivateCapturer();
    CheckDatalink();
    SetupFilter();
}

template<typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetupCaptureLoop(int packet_number, void (*pcap_handler)(u_char *, const pcap_pkthdr *,
                 const u_char *), u_char* args_ptr) {
    m_packet_number = packet_number;
    m_pcap_handler = pcap_handler;
    m_args_ptr = args_ptr;

}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::StartCaptureLoop() {
    pcap_loop(m_pcap_handle, m_packet_number, m_pcap_handler, m_args_ptr);
}

template<typename Detector>
std::string ArpSpoofingDetect::PacketCapturer<Detector>::GetDeviceName() const {
    return m_device;
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetTargetDeviceKeyword(const char *target_device_keyword) {
    m_target_device_keyword = target_device_keyword;
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetTargetDatalink(int target_datalink) {
    m_datalink = target_datalink;
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetFilterExpression(const char* filter_expression) {
    m_filter_expression = filter_expression;
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetSnapLen(int snaplen) {
    m_snaplen = snaplen;
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetPromiscMode(bool active) {
    m_promisc_mode = active;
}

template <typename Detector>
void ArpSpoofingDetect::PacketCapturer<Detector>::SetImmediateMode(bool active) {
    m_immediate_mode = active;
}

ArpSpoofingDetect::ArpSpoofingDetector::ArpSpoofingDetector() {
    // arp_pcap_capturer.SetMessageHandleFn(std::bind(&AddMessage, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), this);
    arp_pcap_capturer.SetMessageHandleFn(&ArpSpoofingDetector::AddMessage, this);

#if defined(_WIN32) || defined(_WIN64)
    arp_pcap_capturer.SetTargetDeviceKeyword("Ethernet");
#elif defined(__APPLE__) || defined(__MACH__)
    arp_pcap_capturer.SetTargetDeviceKeyword("en0");
#endif

    m_device = "en0";

    arp_pcap_capturer.SetTargetDatalink(DLT_EN10MB);
    arp_pcap_capturer.SetFilterExpression("arp");
}

ArpSpoofingDetect::ArpSpoofingDetector::~ArpSpoofingDetector() {
}

uint64_t ArpSpoofingDetect::ArpSpoofingDetector::hex_in_str_to_uint64(const std::string &hex) {
    uint64_t hex_uint64;
    std::stringstream uint64_stream;
    uint64_stream << std::hex << hex;
    uint64_stream >> hex_uint64;
    return hex_uint64;
}

uint32_t ArpSpoofingDetect::ArpSpoofingDetector::hex_in_str_to_uint32(const std::string &hex) {
    uint32_t hex_uint32;
    std::stringstream uint32_stream;
    uint32_stream << std::hex << hex;
    uint32_stream >> hex_uint32;
    return hex_uint32;
}

uint16_t ArpSpoofingDetect::ArpSpoofingDetector::hex_in_str_to_uint16(const std::string &hex) {
    uint16_t hex_uint16;
    std::stringstream uint16_stream;
    uint16_stream << std::hex << hex;
    uint16_stream >> hex_uint16;
    return hex_uint16;
}

uint8_t ArpSpoofingDetect::ArpSpoofingDetector::hex_in_str_to_uint8(const std::string &hex) {
    uint8_t hex_uint8;
    std::stringstream uint8_stream;
    uint8_stream << std::hex << hex;
    uint8_stream >> hex_uint8;
    return hex_uint8;
}

std::string ArpSpoofingDetect::ArpSpoofingDetector::bytes_to_int(const u_char *bytes, size_t len, const char *seperator) {
    std::string bytes_in_int;
    for (size_t i = 0; i < len; i ++) {
        bytes_in_int += std::to_string(bytes[i]);
        if (i < len - 1) bytes_in_int += seperator;
    }
    return bytes_in_int;
}

std::string ArpSpoofingDetect::ArpSpoofingDetector::bytes_to_hex(const u_char *bytes, size_t len, const char *seperator) {
    std::ostringstream hex_stream;
    for (size_t i = 0; i < len; i ++) {
        hex_stream <<  std::hex << std::setfill('0') << std::setw(2) << static_cast<const int>(bytes[i]);
        if (i < len - 1) hex_stream << seperator;
    }
    return hex_stream.str();
}

void ArpSpoofingDetect::ArpSpoofingDetector::GetRouterIPs() {
#if defined(_WIN32) || defined(_WIN64)
    std::array<char, 128> buffer = {};
    std::string command_output_string;
    std::string command = R"(ipconfig /all | findstr /C:"Default Gateway")";
    AddMessage("running command: " + command, false, true);
    std::unique_ptr<FILE, decltype(&close_pipe)> stream(open_pipe(command.c_str(), "r"), close_pipe);
    if (stream == nullptr) {
        AddMessage("popen() failed!", true, true);
        return;
    }
    while (fgets(buffer.data(), buffer.size(), stream.get()) != nullptr) {
        command_output_string += buffer.data();
    }

    command_output_string.erase(command_output_string.find_last_not_of("\r\n") + 1);
    AddMessage(command_output_string, false, true);

    // extract
    std::string router_ip_addr = split(command_output_string, ":")[1];
    router_ip_addr.erase(0, router_ip_addr.find_first_not_of(" \t"));
    router_ip_addr.erase(router_ip_addr.find_last_not_of(" \t") + 1);
    m_RouterIPs = {router_ip_addr};
#elif defined(__APPLE__) || defined(__MACH__)
    std::array<char, 128> buffer = {};
    std::string command_output_string;
    std::string command = "ipconfig getpacket " + m_device + " | grep router";
    AddMessage("running command: " + command, false, true);
    std::unique_ptr<FILE, decltype(&close_pipe)> stream(open_pipe(command.c_str(), "r"), close_pipe);
    if (stream == nullptr) { // equivalent to stream.get() == nullptr
        AddMessage("popen() failed!", true, true);
        return;
    }
    while (fgets(buffer.data(), buffer.size(), stream.get()) != nullptr) {
        command_output_string += buffer.data();
    }

    command_output_string.erase(command_output_string.find_last_not_of("\r\n") + 1);
    AddMessage(command_output_string, false, true);

    // extract
    size_t routers_start_idx = command_output_string.find('{');
    size_t routers_end_idx = command_output_string.find('}');
    if (routers_start_idx != std::string::npos && routers_end_idx != std::string::npos) {
        if (routers_start_idx + 1 == routers_end_idx) {
            AddMessage("NO routers found!", true, true);
            return;
        }

        std::unordered_set<std::string> router_ips_set;
        std::string routers;
        std::string router_ip;

        routers = command_output_string.substr(routers_start_idx + 1, routers_end_idx - routers_start_idx - 1);
        std::istringstream ip_stream(routers);
        while (std::getline(ip_stream, router_ip, ',')) {
            router_ip.erase(0, router_ip.find_first_not_of(" \t"));
            router_ip.erase(router_ip.find_last_not_of(" \t") + 1);
            if (!router_ip.empty()) {
                router_ips_set.insert(router_ip);
            }
            else break;
        }
        for (auto& router_ip_addr : router_ips_set) {
            AddMessage(router_ip_addr, false, false);
        }
        m_RouterIPs = router_ips_set;
        return;
    }
    AddMessage("NO routers found!", true, true);
    return;
#endif
    AddMessage("Unsupported Platform", true, true);
}

void ArpSpoofingDetect::ArpSpoofingDetector::SetupDHCPLeaseTime() {
#if defined(_WIN32) || defined(_WIN64)
    std::array<char, 128> buffer = {};
    std::string command_output_string;
    std::string command = R"(ipconfig /all | findstr /C:"DHCP Enabled" /C:"Lease Obtained" /C:"Lease Expires")";
    AddMessage("running command: " + command, false, true);
    std::unique_ptr<FILE, decltype(&close_pipe)> stream(open_pipe(command.c_str(), "r"), close_pipe);
    if (stream == nullptr) {
        AddMessage("popen() failed!", true, true);
        return;
    }
    while (fgets(buffer.data(), buffer.size(), stream.get()) != nullptr) {
        command_output_string += buffer.data();
    }

    command_output_string.erase(command_output_string.find_last_not_of("\r\n") + 1);
    AddMessage(command_output_string, false, true);

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
    AddMessage(DHCP_state_str, false, true);
    AddMessage(lease_obtained, false, true);
    AddMessage(lease_expires, false, true);
    if (DHCP_state_str.empty() || lease_obtained.empty() || lease_expires.empty() || DHCP_state_str == "No") {
        AddMessage("DHCP lease time not found", true, true);
        return;
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
    start_time_info.tm_year = std::stoi(start_time_data_vector[3]) - 1900;
    start_time_info.tm_hour = std::stoi(start_time_data_vector[4]);
    start_time_info.tm_min = std::stoi(start_time_data_vector[5]);
    start_time_info.tm_sec = std::stoi(start_time_data_vector[6]);
    if (start_time_data_vector[7] == "pm") start_time_info.tm_hour += 12;
    std::time_t start_t = std::mktime(&start_time_info);

    std::vector<std::string> end_time_data_vector = split(lease_expires, " ,:");

    end_time_info.tm_mday = std::stoi(end_time_data_vector[1]);
    end_time_info.tm_mon = months[end_time_data_vector[2]];
    end_time_info.tm_year = std::stoi(end_time_data_vector[3]) - 1900;
    end_time_info.tm_hour = std::stoi(end_time_data_vector[4]);
    end_time_info.tm_min = std::stoi(end_time_data_vector[5]);
    end_time_info.tm_sec = std::stoi(end_time_data_vector[6]);
    if (end_time_data_vector[7] == "pm") end_time_info.tm_hour += 12;
    std::time_t end_t = std::mktime(&end_time_info);

    if (start_t < 0 || end_t < 0) {
        AddMessage("unrecognizable time", true, true);
        return;
    }

    m_DHCPLeaseTime = end_t - start_t;
#elif defined(__APPLE__) || defined(__MACH__)
    std::array<char, 128> buffer = {};
    std::string command_output_string;
    std::string command = "ipconfig getpacket " + m_device + " | grep lease_time";
    AddMessage("running command: " + command, false, true);
    std::unique_ptr<FILE, decltype(&close_pipe)> stream(open_pipe(command.c_str(), "r"), close_pipe);
    if (stream == nullptr) { // equivalent to stream.get() == nullptr
        AddMessage("popen() failed", true, true);
        return;
    }
    while (fgets(buffer.data(), buffer.size(), stream.get()) != nullptr) {
        command_output_string += buffer.data();
    }

    command_output_string.erase(command_output_string.find_last_not_of('\n') + 1);
    AddMessage(command_output_string, false, true);

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
        AddMessage("cannot identify dhcp lease time", true, true);
        return;
    }

    // convert value in string to value in corresponding data_type
    // if (data_type == "uint64") {
    //     m_DHCPLeaseTime = hex_in_str_to_uint64(value);
    //     return;
    // }
    if (data_type == "uint32") {
        m_DHCPLeaseTime = hex_in_str_to_uint32(value);
        return;
    }
    if (data_type == "uint16") {
        m_DHCPLeaseTime = hex_in_str_to_uint16(value);
        return;
    }
    if (data_type == "uint8") {
        m_DHCPLeaseTime = hex_in_str_to_uint8(value);
        return;
    }
    AddMessage("unknown dhcp lease time type (e.g. uint32)", true, true);
    return;
#endif
    AddMessage("Unsupported Platform", true, true);
}

void ArpSpoofingDetect::ArpSpoofingDetector::SetupDetector() {
    arp_pcap_capturer.SetupCapturer();
    GetRouterIPs();
    SetupDHCPLeaseTime();
}

void ArpSpoofingDetect::ArpSpoofingDetector::StartCapture() {
    arp_pcap_capturer.SetupCaptureLoop(0, [](u_char *args, const pcap_pkthdr *header, const u_char *packet) {
        auto* detector_ptr = reinterpret_cast<ArpSpoofingDetector*>(args);
        detector_ptr->CaptureLoop(args, header, packet);
    }, reinterpret_cast<u_char*>(this));
    arp_pcap_capturer.StartCaptureLoop();
}

void ArpSpoofingDetect::ArpSpoofingDetector::CaptureLoop(u_char *args, const pcap_pkthdr *header, const u_char *packet) {
    // packet
    // ethernet header + payload (in this case, arp header)
    std::cout << "Packet captured: Length = " << header->len << std::endl;

    const auto *packet_header = reinterpret_cast<const ethernet_header *>(packet);
    if (ntohs(packet_header->ether_type) != ETHERTYPE_ARP) return;

    const auto *arp_header = reinterpret_cast<const ether_arp_header *>(packet + sizeof(ethernet_header)); // move the pointer to the arp header

    std::string sender_mac = bytes_to_hex(arp_header->sender_mac, 6, ":");
    std::string sender_ip = bytes_to_int(arp_header->sender_ip, 4, ".");
    std::string target_mac = bytes_to_hex(arp_header->target_mac, 6, ":");
    std::string target_ip = bytes_to_int(arp_header->target_ip, 4, ".");

    std::cout << "ARP sender MAC address: " << sender_mac << std::endl;
    std::cout << "ARP sender Protocol address (IP): " << sender_ip << std::endl;
    std::cout << "ARP target MAC address: " << target_mac << std::endl;
    std::cout << "ARP target Protocol address (IP): " << target_ip << std::endl;
    std::cout << std::endl;

    std::time_t current_time = std::time(nullptr);
    // check sender mac-ip pair
    if (m_MacToIPMap.find(sender_mac) == m_MacToIPMap.end()) {
        if (m_RouterIPs.find(sender_mac) == m_RouterIPs.end()) {
            m_MacToIPMap.insert({sender_mac, ActivePrivateNetworkIP(sender_ip, current_time)});
        }
        else {
            m_MacToIPMap.insert({sender_mac, ActivePrivateNetworkIP(sender_ip, current_time, true)});
        }
    }
    else {
        auto& entry = m_MacToIPMap.at(sender_mac);
        if (!entry.ip_equals_to(sender_ip)) {
            if (entry.if_router() || entry.calc_time_pass(current_time) < m_DHCPLeaseTime) {
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
        if (m_MacToIPMap.find(target_mac) == m_MacToIPMap.end()) {
            m_MacToIPMap.insert({target_mac, ActivePrivateNetworkIP(target_ip, current_time)});
        }
        else {
            auto& entry = m_MacToIPMap.at(target_mac);
            if (!entry.ip_equals_to(target_ip)) {
                if (entry.if_router() || entry.calc_time_pass(current_time < m_DHCPLeaseTime)) {
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
}

void ArpSpoofingDetect::ArpSpoofingDetector::AddMessage(const std::string &new_message, const bool& raise_error, bool end_line) {
    m_messages[m_messages.size() - 1] += new_message;
    if (end_line) m_messages.emplace_back("");
    if (raise_error) {
        throw std::runtime_error(new_message);
    }
}

const std::vector<std::string> & ArpSpoofingDetect::ArpSpoofingDetector::GetMessages() {
    return m_messages;
}

void ArpSpoofingDetect::ArpSpoofingDetector::ClearMessages() {
    m_messages.clear();
}
