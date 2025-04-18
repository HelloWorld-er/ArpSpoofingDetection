# ArpSpoofingDetection
## Introduction
This app is used to capture arp packets sent through your current device.

By analyzing these arp packets, we can somehow detect if arp spoofing is happening in your current Ethernet.
- Targeting on your current device

  We can analyze if there is arp spoofing targeting on your current device by looking at the change in IP-Mac Pairs of the gateway.

  We are confident at detecting if any arp spoofing is currently targeting on your device!

- Targeting on other people's devices

  We can analyze if there is arp spoofing targeting on other devices on the same Ethernet by looking at the change in IP-Mac Pairs and the DHCP Lease Time

This app cannot 100%% detect arp spoofing, but we at least make it difficult for attackers!

## How to setup
1. Download the source code

2. Install the required libraries and tools
   - install git version control tool if I do not have it on your device. Visit the webpage https://git-scm.com/downloads
   - open the source code directory in your terminal
   - clone this project under a folder (anywhere you want)
     ```
     git clone https://github.com/HelloWorld-er/ArpSpoofingDetection.git
     ```
   - run the command to clone the repository of glfw
     ```
     git clone https://github.com/glfw/glfw.git
     ```
   - and then run the command to clone the repository of imgui
     ```
     git clone https://github.com/ocornut/imgui.git -b docking
     ```
   - Install Vulkan SDK. Visit the webpage https://vulkan.lunarg.com/sdk/home
     - Download and Install it.
     - When it asks you to select the components required, the default is enough. 
   - Install Libpcap library
     - if you are on Windows, you have to install Npcap SDK by yourself.
       - visit the webpage https://nmap.org/npcap/#download
       - download the latest version of Npcap SDK and install it
       - By default, Npcap SDK will be installed in C:\Program Files\Npcap. If you changed the location of the folder, change CMakeLists.txt as well.
     - if you are on MacOS, you do not need to install libpcap by yourself, since it is installed in MacOS system by default.
       > if you cannot run the program because lipcap isn't found, install libpcap library by running the following command:
           ```
           brew install libpcap
           ```
   - Install cmake
     - if you are on Windows, visit the webpage https://cmake.org/download/
     - if you are on MacOS, run the following command in your terminal:
       ```
       brew install cmake
       ```
3. Build the app
   - open the source code directory in your terminal
   - run the following command, step by step
     ```
     cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
     ```
     ```
     cmake --build build --config Release
     ```
     ```
     install_name_tool -add_rpath /usr/local/lib build/ArpSpoofingDetector.app/Contents/MacOS/ArpSpoofingDetector
     ```
   - open the build directory, you will see a file named ArpSpoofingDetector which is the application file.
   - you can duplicate or move the file to your desktop. That file is the application itself.
   