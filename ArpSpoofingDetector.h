//
// Created by Yimin Liu on 14/4/2025.
//
#pragma once
#include <iostream>

#ifndef ARPSPOOFINGDETECTOR_H
#define ARPSPOOFINGDETECTOR_H

#include "ether_structure.h"


#ifndef _LIBCPP_VECTOR
#include <vector>
#endif

#ifndef _LIBCPP_STRING
#include <string>
#endif

#ifndef _LIBCPP_FUNCTIONAL
#include <functional>
#endif


#ifndef _LIBCPP_UNORDERED_SET
#include <unordered_set>
#endif

#ifndef _LIBCPP_CSTDINT
#include <cstdint> // for uint32 uint16 ...
#endif


#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#include <pcap/pcap.h>
#include <pcap/dlt.h>
auto& open_pipe = _popen;
auto& close_pipe = _pclose;
#elif defined(__APPLE__) || defined(__MACH__)
#include <arpa/inet.h>
#include <pcap/pcap.h> // pcap
#include <pcap/dlt.h> // macro defined DLTxxx
#endif


namespace ArpSpoofingDetect {
#if defined(_WIN32) || defined(_WIN64)
    static auto& open_pipe = _popen;
    static auto& close_pipe = _pclose;
#elif defined(__APPLE__) || defined(__MACH__)
    static auto& open_pipe = popen;
    static auto& close_pipe = pclose;
#endif


    class PacketCapturer {
    public:
        PacketCapturer();
        ~PacketCapturer();

        void SetMessageHandleFn(void(*message_handle_fn)(const std::string& new_message, const bool& raise_error, bool end_line));

        void InitCapturer();
        bool CheckGeneralSignal(int signal, int success_signal, const std::string &prefix, pcap_t* pcap_handle) const;
        static bool IfPcapDevDescExist(pcap_if_t device);
        void CheckAvailableDevices(); // for outside of scope
        void GetDevice();
        void InitPcapHandle();
        void ActivateCapturer();
        void CheckDatalink();
        void SetupFilter();
        void SetupCapturer();
        void SetupCaptureLoop(int packet_number, void (*pcap_handler)(u_char *, const pcap_pkthdr *,
                 const u_char *), u_char* args_ptr);
        void StartCaptureLoop();

        std::string GetDeviceName() const;

        void SetTargetDeviceKeyword(const char* target_device_keyword); // "en0" for mac; "Ethernet" for windows
        void SetTargetDatalink(int target_datalink); // DLT_EN10MB
        void SetFilterExpression(const char* filter_expression); // "arp"

        void SetSnapLen(int snaplen);
        void SetPromiscMode(bool active);
        void SetImmediateMode(bool active);
    private:

        std::function<void(const std::string&, const bool&, bool)> AddMessage;
        // void(Detector::*AddMessage)(const std::string& new_message, const bool& raise_error, bool end_line);

        char m_error_buf[PCAP_ERRBUF_SIZE];
        std::string m_message;
        std::string m_device = "any";
        pcap_t *m_pcap_handle;

        std::string m_target_device_keyword;
        int m_datalink;
        std::string m_filter_expression;

        int m_snaplen = 65535;
        bool m_promisc_mode = true;
        bool m_immediate_mode = true;

        int m_packet_number;
        void (*m_pcap_handler)(u_char *, const pcap_pkthdr *,
                 const u_char *);
        u_char* m_args_ptr;

    };

    class IPAddressEntity;
    class MACAddressEntity;

    class IPAddressEntity {
    public:
        explicit IPAddressEntity(const std::string& ip, const std::time_t& last_seen, bool is_router);
        ~IPAddressEntity();
        void SetMAC(MACAddressEntity* mac_ptr);
        const std::string& GetIPAddress() const;
        MACAddressEntity* GetMACAddressEntities() const;

        void SetRouter();
        void refresh_last_time(std::time_t new_last_seen) {
            m_last_seen_time = new_last_seen;
        }
        std::time_t calc_time_pass(const std::time_t& new_last_seen) const {
            return new_last_seen - m_last_seen_time;
        }
        bool ip_equals_to(const std::string& ip_addr) const {
            return m_ip == ip_addr;
        }
        bool if_router() const {
            return m_is_router;
        }
        bool operator==(const IPAddressEntity& other) const {
            return m_ip == other.GetIPAddress();
        }
        bool operator!=(const IPAddressEntity& other) const {
            return m_ip != other.GetIPAddress();
        }
    private:
        std::time_t m_last_seen_time;
        bool m_is_router = false;

        std::string m_ip;
        MACAddressEntity* m_mac_ptr = nullptr;
    };

    class MACAddressEntity {
    public:
        explicit MACAddressEntity(const std::string& mac);
        ~MACAddressEntity();
        void SetIP(IPAddressEntity* ip_ptr);
        const std::string& GetMACAddress() const;
        IPAddressEntity* GetIPAddressEntity() const;
        bool operator==(const MACAddressEntity& other) const {
            return m_mac == other.GetMACAddress();
        }
        bool operator!=(const MACAddressEntity& other) const {
            return m_mac != other.GetMACAddress();
        }
    private:
        std::string m_mac = "00:00:00:00:00:00";
        IPAddressEntity* m_ip_ptr = nullptr;

    };


    class ArpSpoofingDetector {
    public:
        PacketCapturer arp_pcap_capturer;

        ArpSpoofingDetector(void(*MessageHandler)(const std::string &new_message, const bool& raise_error, bool end_line), bool(*IfStopCaptureLoopFn)());
        ~ArpSpoofingDetector();
        static uint64_t hex_in_str_to_uint64(const std::string &hex);
        static uint32_t hex_in_str_to_uint32(const std::string &hex);
        static uint16_t hex_in_str_to_uint16(const std::string &hex);
        static uint8_t hex_in_str_to_uint8(const std::string &hex);
        static std::string bytes_to_int(const u_char *bytes, size_t len, const char* seperator = "");
        static std::string bytes_to_hex(const u_char *bytes, size_t len, const char* seperator = "");
        void GetRouterIPs();
        void SetupDHCPLeaseTime();
        void SetupDetector();
        void StartCapture();

        void CaptureLoop(u_char *args, const pcap_pkthdr *header, const u_char *packet);

    private:
        std::function<bool()> IfStopCaptureLoop;

        std::function<void(const std::string&, const bool&, bool)> AddMessage;

        std::string m_device = "en0";
        std::vector<std::string> m_messages = {""};
        std::unordered_set<std::string> m_RouterIPs {};
        long long m_DHCPLeaseTime = 0;

        std::unordered_map<std::string, MACAddressEntity> m_MACList;
        std::unordered_map<std::string, IPAddressEntity> m_IPList;

        const std::string unknown_mac_address = "00:00:00:00:00:00";
    };
}



#endif //ARPSPOOFINGDETECTOR_H
