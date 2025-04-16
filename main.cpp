#include <iostream>
#include <thread>
#include <mutex>

#include "ArpSpoofingDetector.h"
#include "UI.h"

#include <unordered_map>


class SharedData {
private:
    std::vector<std::string> m_data {""};    // The shared resource
    std::vector<std::string> m_setup_info {};
    bool m_setup_detector = false;
    bool m_stop_capture = true;

    std::mutex mtx;           // The mutex protecting the shared resource
public:
    bool if_stop_capture() {
        std::lock_guard<std::mutex> lock(mtx);
        return m_stop_capture;
    }
    void start_capture() {
        std::lock_guard<std::mutex> lock(mtx);
        m_stop_capture = false;
    }

    void stop_capture() {
        std::lock_guard<std::mutex> lock(mtx);
        m_stop_capture = true;
    }

    void setup_detector_finish() {
        std::lock_guard<std::mutex> lock(mtx);
        m_setup_info = m_data;
        m_data.clear();
        m_data.emplace_back("");
        m_setup_detector = true;
    }

    const std::vector<std::string>& get_setup_info() {
        std::lock_guard<std::mutex> lock(mtx);
        return m_setup_info;
    }

    bool if_setup_detector() {
        std::lock_guard<std::mutex> lock(mtx);
        return m_setup_detector;
    }

    void clear_messages() {
        std::lock_guard<std::mutex> lock(mtx);
        m_data.clear();
        m_data.emplace_back("");
    }
    // Safely add data to the shared resource
    void add_message(const std::string &new_message, const bool& raise_error, bool end_line) {
        std::lock_guard<std::mutex> lock(mtx);
        m_data[m_data.size() - 1] += new_message;
        if (end_line) m_data.emplace_back("");
        if (raise_error) {
            throw std::runtime_error(new_message);
        }
    }

    // Safely print the shared resource
    const std::vector<std::string>& get_messages() {
        std::lock_guard<std::mutex> lock(mtx);
        return m_data;
    }
};

SharedData sharedData;


static UI::UILayer ui_layer;

bool g_error_occurred = false;

static void HelpMarker(const char*);
void open_welcome_page(bool* p_open);
void open_capture_page(bool* p_open);
void start_ui();
void setup_ui();
void start_capture();


static void HelpMarker(const char* desc)
{
    ImGui::TextDisabled("(?)");
    if (ImGui::BeginItemTooltip())
    {
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}


void open_welcome_page(bool* p_open) {
    static ImGuiWindowFlags flags;

    if (ImGui::Begin("Welcome Page", p_open, flags))
    {

        // ImGui::PushTextWrapPos(ImGui::GetContentRegionAvail().x); // Set wrap width to available space

        ImGui::Text("Arp Spoofing Detector");
        ImGui::SameLine();
        HelpMarker("Arp Spoofing is a kind of middle-man attack.");
        ImGui::Spacing();

        if (ImGui::CollapsingHeader("Introduction")) {
            ImGui::TextWrapped("This app is used to capture arp packets sent through your current device");
            ImGui::TextWrapped("By analyzing these arp packets, we can somehow detect if arp spoofing is happening in your current Ethernet");
            if (ImGui::TreeNode("Targeting on your current device")) {
                ImGui::TextWrapped("We can analyze if there is arp spoofing targeting on your current device by looking at the change in IP-Mac Pairs of the gateway.");
                ImGui::Spacing();
                ImGui::TextWrapped("We are confident at detecting if any arp spoofing is currently targeting on your device!");
                ImGui::TreePop();
            }
            if (ImGui::TreeNode("Targeting on other people's devices")) {
                ImGui::TextWrapped("We can analyze if there is arp spoofing targeting on other devices on the same Ethernet by looking at the change in IP-Mac Pairs and the DHCP Lease Time");
                ImGui::TreePop();
            }
            ImGui::TextWrapped("This app cannot 100%% detect arp spoofing, but we at least make it difficult for attackers!");
        }
        if (ImGui::CollapsingHeader("What is Arp")) {
            ImGui::TextWrapped(
                "ARP stands for Address Resolution Protocol. ARP is only used in local network.");
            ImGui::TextWrapped("Every time your device wants to communicate with other device, it sends an ARP "
                               "packet to the router, and the router will send the packet received from your device "
                               "to the target device, since the router has a IP-to-MAC mapping table formed by sending requests to all devices in the local network.");
            ImGui::TextWrapped("MAC address is the address that is an universal identifier, which means there are "
                               "no two devices have the same MAC address in the world.");
            ImGui::TextWrapped("Generally, within a local network, your device will only know your target device's IP address. "
                               "In order to be able to communicate with the target address, you have to know the MAC address which is the identifier. "
                               "By sending the ARP packet, we retrieve the target MAC address, so that your device can start to communicate with the target device.");
        }
        if (ImGui::CollapsingHeader("What is Arp Spoofing")) {
            ImGui::TextWrapped("Arp Spoofing is a kind of middle-man attack. The attackers can use arp spoofing to capture the data you send to other devices.");
            ImGui::TextWrapped("So, how do attackers perform arp spoofing? Since this kind of IP-to-MAC mapping is based on the router, attackers can modify their "
                               "response to the router, meanwhile, they can also send out arp packets to the victim device and say that they are actually the router.");
            ImGui::TextWrapped("By doing so, the victim device will send all their packets to the attacker's device. The attacker device can capture packets sent "
                               "from the victim device and manipulate the data. Everything can be unsafe!");
        }
        if (ImGui::CollapsingHeader("How do people solve Arp Spoofing issue nowadays")) {
            ImGui::TextWrapped("Nowadays, people generally use encryption techniques to solve the issue.");
            ImGui::TextWrapped("Even though attackers can use arp spoofing capture packets, if the packets is encrypted, attackers have no ways "
                               "to get any useful information. Therefore, protocols like HTTPS is introduced worldwide.");
        }
        if (ImGui::CollapsingHeader("Potential issues of nowadays solution")) {
            ImGui::TextWrapped("Arp Spoofing issue is not actually solved directly. Even though we have encrypted methods, "
                               "some weak, unsafe protocols are still in usage. For example, there are still some websites are using HTTP.");
            ImGui::TextWrapped("Even though you may argue that people generally won't have important information on those unsafe websites, but "
                               "we believe important information may be indirectly captured.");
            ImGui::Spacing();
            ImGui::TextWrapped("For example, if you have an account on an unsafe website, we may have nothing stored in that account, but your account name "
                               "and your password will be captured. What if you use a same or a similar password on several "
                               "platforms or any other account? Attackers can use your password to log into your other accounts which "
                               "may contain significant information of yourself.");
            ImGui::Spacing();
            ImGui::TextWrapped("So how do our app try to directly solve the arp spoofing issue? See the introduction section.");
        }
        if (ImGui::CollapsingHeader("Limitation of this app")) {
            ImGui::TextWrapped("This app has not considered the existence of virtual machines in the Ethernet yet.");
        }
        if (ImGui::CollapsingHeader("Acknowledgement")) {
            ImGui::Text("This app is built 100%% by using C++, which used several external libraries");
            if (ImGui::TreeNode("packet capturing libraries")) {
                ImGui::TextWrapped("For packet capturing, we used libpcap in MacOS and Npcap in Windows");
                ImGui::TreePop();
            }
            if (ImGui::TreeNode("UI design libraries")) {
                ImGui::TextWrapped("For UI design, we used ImGui, Vulkan, and GLFW.");
                ImGui::TreePop();
            }
        }

        // ImGui::PopTextWrapPos(); // Restore default wrap behavior
    }
    ImGui::End();
}

void open_capture_page(bool* p_open) {
    static ImGuiWindowFlags flags;
    static bool if_capture = false;

    if (ImGui::Begin("Capture Page", p_open, flags)) {
        if (!if_capture && ImGui::Button("Start Capture")) {
            if_capture = true;
            sharedData.clear_messages();
            sharedData.start_capture();
            std::thread capture_loop(start_capture);
            capture_loop.detach();
        }
        if (if_capture && ImGui::Button("Stop Capture")) {
            sharedData.stop_capture();
            if_capture = false;
        }
        ImGui::Separator();
        ImGui::Text("Logs:");
        if (sharedData.if_setup_detector()) {
            for (auto& message: sharedData.get_setup_info()) {
                ImGui::TextWrapped("%s", message.c_str());
            }
            ImGui::Separator();
            for (auto& message: sharedData.get_messages()) {
                ImGui::TextWrapped("%s", message.c_str());
            }
        }


        ImVec2 center = ImGui::GetMainViewport()->GetCenter();
        ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

        if (g_error_occurred) {
            ImGui::OpenPopup("Find an Error!");
        }
        if (ImGui::BeginPopupModal("Find an Error!", &g_error_occurred, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("An error is found!");
            for (auto& message: sharedData.get_messages()) {
                ImGui::Text("%s", message.c_str());
            }
            ImGui::EndPopup();
        }
    }
    ImGui::End();
}

void start_ui() {
    static bool show_demo = true;
    static bool use_work_area = true;
    static bool show_welcome_page = true;
    static bool show_capture_page = true;

    while (!ui_layer.IfWindowShouldClose()) {
        ui_layer.StartOfMainLoop();
        if (ui_layer.IfSkipMainLoop()) continue;

        const ImGuiViewport* viewport = ImGui::GetMainViewport();

        // Create the DockSpace
        ImGui::DockSpaceOverViewport(viewport->ID, viewport, ImGuiDockNodeFlags_None);
        // ImGui::ShowDemoWindow(&show_demo);

        // Set windows' positions
        ImGui::SetNextWindowPos(use_work_area ? viewport->WorkPos : viewport->Pos, ImGuiCond_Once);
        ImGui::SetNextWindowSize(use_work_area ? ImVec2(viewport->WorkSize.x/2, viewport->WorkSize.y) : ImVec2(viewport->Size.x/2, viewport->Size.y), ImGuiCond_Once);

        // ImGui::ShowDemoWindow(&show_demo);
        // add components/windows above the main windows
        open_welcome_page(&show_welcome_page);

        ImGui::SetNextWindowPos(use_work_area
                                    ? ImVec2(viewport->WorkPos.x + viewport->WorkSize.x / 2, viewport->WorkPos.y)
                                    : ImVec2(viewport->Pos.x + viewport->Size.x / 2, viewport->Pos.y), ImGuiCond_Once);
        ImGui::SetNextWindowSize(use_work_area ? ImVec2(viewport->WorkSize.x/2, viewport->WorkSize.y) : ImVec2(viewport->Size.x/2, viewport->Size.y), ImGuiCond_Once);

        open_capture_page(&show_capture_page);

        ui_layer.EndOfMainLoop();
    }
    ui_layer.CleanUp();
}

void setup_ui() {
    ui_layer.SetWindowTitle("Arp Spoofing Detector");
    ui_layer.SetClearColor(ImVec4(0, 0, 0, 1));

    ui_layer.SetupUI();
    ui_layer.SetFontFile("./resources/fonts/DIN Alternate Bold.ttf");
    ui_layer.SetFontSize(40.0f);
    ImGui::StyleColorsLight();
}


void start_capture() {
    ArpSpoofingDetect::ArpSpoofingDetector arp_spoofing_detector([](const std::string &new_message, const bool& raise_error, bool end_line) {
    sharedData.add_message(new_message, raise_error, end_line);
}, []()-> bool {
    return sharedData.if_stop_capture();
});
    try {
        arp_spoofing_detector.SetupDetector();
    } catch (...) {
        g_error_occurred = true;
    }
    sharedData.setup_detector_finish();
    try {
        arp_spoofing_detector.StartCapture();
    } catch (std::runtime_error& exception_info) {
        std::cout << exception_info.what() << std::endl;
    }
}


int main() {
    setup_ui();
    start_ui();
    return 0;
}