#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <pcap.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

// Struct to store network device information
struct NetworkDevice {
    std::string name;
    std::string description;
};

// Struct to store packet information
struct PacketInfo {
    std::string timestamp;
    std::string source;
    std::string destination;
    int size;
    std::string protocol;
};

std::vector<NetworkDevice> network_devices;
std::vector<PacketInfo> captured_packets;
//std::mutex packets_mutex;  // Corrected typo here
std::atomic<bool> capture_running(false);
std::string selected_device;

void setup_imgui(GLFWwindow* window);
void cleanup_imgui();
void list_network_devices();
void capture_packets(const std::string& device_name);
void render_ui();

int main() {
    // Initialize GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }

    // Create window using GLFW
    GLFWwindow* window = glfwCreateWindow(1280, 720, "Advanced Network Monitor", nullptr, nullptr);
    if (!window) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return -1;
    }

    // Setup OpenGL context and set the window as current
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // Setup ImGui
    setup_imgui(window);

    // List available network devices
    list_network_devices();

    // Create a separate thread for capturing network packets
    std::thread capture_thread;

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        // Poll events
        glfwPollEvents();

        // Start new ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Render the UI
        render_ui();

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        // Swap buffers
        glfwSwapBuffers(window);
    }

    // Stop the packet capture and join the thread
    capture_running = false;
    if (capture_thread.joinable()) {
        capture_thread.join();
    }

    // Clean up ImGui and GLFW
    cleanup_imgui();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}

void setup_imgui(GLFWwindow* window) {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");
}

void cleanup_imgui() {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
}

void list_network_devices() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find all network devices available for packet capture
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }

    // Add network devices to the list
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        network_devices.push_back({dev->name, dev->description ? dev->description : "No description available"});
    }

    // Free the device list after use
    pcap_freealldevs(alldevs);
}

void capture_packets(const std::string& device_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device_name.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    // Capture packets in a loop while capture is running
    while (capture_running) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");

        PacketInfo info;
        info.timestamp = ss.str();
        info.size = header->len;
        info.protocol = "Unknown";  // You can add protocol detection logic here

        // Basic Ethernet header parsing (assuming Ethernet II)
        if (header->len >= 14) {
            char src_mac[18], dst_mac[18];
            snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
            snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
            info.source = src_mac;
            info.destination = dst_mac;
        }

        std::lock_guard<std::mutex> lock(packets_mutex);
        captured_packets.push_back(info);
        if (captured_packets.size() > 1000) {
            captured_packets.erase(captured_packets.begin());
        }
    }

    pcap_close(handle);
}

void render_ui() {
    ImGui::Begin("Network Monitor");

    // Combo box for selecting network devices
    if (ImGui::BeginCombo("Network Devices", selected_device.c_str())) {
        for (const auto& device : network_devices) {
            bool is_selected = (selected_device == device.name);
            if (ImGui::Selectable(device.name.c_str(), is_selected)) {
                selected_device = device.name;
            }
            if (is_selected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    // Start/Stop capture buttons
    if (!capture_running && ImGui::Button("Start Capture")) {
        if (!selected_device.empty()) {
            capture_running = true;
            std::thread capture_thread(capture_packets, selected_device);
            capture_thread.detach();  // Detach the capture thread to run in background
        }
    }
    ImGui::SameLine();
    if (capture_running && ImGui::Button("Stop Capture")) {
        capture_running = false;
    }

    // Display the number of captured packets
    ImGui::Text("Captured Packets: %zu", captured_packets.size());

    // Table to display packet information
    if (ImGui::BeginTable("Packets", 5, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Timestamp");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Destination");
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("Protocol");
        ImGui::TableHeadersRow();

        std::lock_guard<std::mutex> lock(packets_mutex);
        for (const auto& packet : captured_packets) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%s", packet.timestamp.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s", packet.source.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", packet.destination.c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%d", packet.size);
            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%s", packet.protocol.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::End();
}
