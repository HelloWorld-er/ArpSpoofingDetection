#include <iostream>

#include "ArpSpoofingDetector.h"

int main() {
    ArpSpoofingDetect::ArpSpoofingDetector arp_spoofing_detector;
    try {
        arp_spoofing_detector.SetupDetector();
        for (auto& message: arp_spoofing_detector.GetMessages()) {
            std::cout << message << std::endl;
        }
        arp_spoofing_detector.ClearMessages();
        arp_spoofing_detector.StartCapture();
    } catch (...) {
        for (auto& message: arp_spoofing_detector.GetMessages()) {
            std::cout << message << std::endl;
        }
    }

    return 0;
}