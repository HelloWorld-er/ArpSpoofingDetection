//
// Created by Yimin Liu on 15/4/2025.
//

#ifndef UI_H
#define UI_H

#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_vulkan.h"

#ifndef _LIBCPP_CSTDINT
#include <cstdint>
#endif

#ifndef _LIBCPP_STRING
#include <string>
#endif

#define GLFW_INCLUDE_NONE
#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>


// Volk headers
#ifdef IMGUI_IMPL_VULKAN_USE_VOLK
#define VOLK_IMPLEMENTATION
#include <volk.h>
#endif

//#define APP_USE_UNLIMITED_FRAME_RATE
#ifdef _DEBUG
#define APP_USE_VULKAN_DEBUG_REPORT
#endif

static VkAllocationCallbacks*   g_Allocator = nullptr;
static VkInstance               g_Instance = VK_NULL_HANDLE;
static VkPhysicalDevice         g_PhysicalDevice = VK_NULL_HANDLE;
static VkDevice                 g_Device = VK_NULL_HANDLE;
static uint32_t                 g_QueueFamily = static_cast<uint32_t>(-1);
static VkQueue                  g_Queue = VK_NULL_HANDLE;

static VkPipelineCache          g_PipelineCache = VK_NULL_HANDLE;
static VkDescriptorPool         g_DescriptorPool = VK_NULL_HANDLE;

static ImGui_ImplVulkanH_Window g_MainWindowData;
static uint32_t                 g_MinImageCount = 2;
static bool                     g_SwapChainRebuild = false;

namespace UI {

     class GLFWLayer {
     public:
          GLFWLayer();
          ~GLFWLayer();
          static GLFWwindow* CreateWindow(int hint, int value, const std::string& window_title);
          static void SetErrorCallback();
          static void GLFWInit();
          static void glfw_error_callback(int error, const char* discription);
     };
     class VulkanLayer {
     public:
          VulkanLayer();
          ~VulkanLayer();
          static void check_vk_result(::VkResult err);
          static void SetupVulkan(ImVector<const char*> instance_extensions);
          static void SetupVulkanWindow(ImGui_ImplVulkanH_Window* wd, VkSurfaceKHR surface, int width, int height);
          static bool IsExtensionAvailable(const ImVector<VkExtensionProperties>& properties, const char* extension);
          static void CleanupVulkanWindow();
          static void CleanupVulkan();
     };
     class ImGuiLayer {
     public:
          ImGuiLayer();
          ~ImGuiLayer();
          static GLFWwindow* CreateWindowWithVulkanContext(const std::string& window_title);
          static void SetupImGuiContext();
          static void SetupImGuiStyle();
          static void SetupRendererBackend(GLFWwindow*& window, ImGui_ImplVulkanH_Window*& wd);
          static void LoadFonts(const char* filename, float size_pixels, const ImFontConfig* font_cfg_template, const ImWchar* glyph_ranges);
          static void FrameRender(ImGui_ImplVulkanH_Window* wd, ImDrawData* draw_data);
          static void FramePresent(ImGui_ImplVulkanH_Window* wd);
     private:
     };

     class UILayer {
     public:
          UILayer();
          ~UILayer();
          void SetWindowTitle(const std::string& window_title);
          void SetClearColor(const ImVec4& clear_color);
          void SetFontFile(const std::string& filename);
          void SetFontSize(float size);
          void SetupUI();
          bool IfWindowShouldClose() const;
          bool IfSkipMainLoop() const;
          void StartOfMainLoop();
          void EndOfMainLoop();
          void CleanUp();
     private:
          std::string m_window_title;
          GLFWwindow* m_window = nullptr;
          VkSurfaceKHR m_surface{};
          VkResult m_err;
          ImGui_ImplVulkanH_Window* m_wd = nullptr;
          std::string m_filename;
          float m_font_size_pixel = 16.0f;
          bool m_skip_loop = false;

          // custom
          ImVec4 m_clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
     };
}


#endif //UI_H
