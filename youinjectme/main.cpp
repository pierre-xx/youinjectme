#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "imgui_stdlib.h"
#include <d3d11.h>
#include <tchar.h>
#include <string>
#include <filesystem>
#include "./core/injector.h"
#include "./core/renderer.h"

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR, int) {
    /* init */
	Renderer render;
	if (!render.init()) return 1;

	Injector injector;

    std::string dllName;
    bool show = true;

    /* render loop */
	while (render.running() && show) {
		render.begin();

        ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImVec2 center = viewport->GetCenter();

        ImGui::SetNextWindowPos(center, ImGuiCond_Once, ImVec2(0.5f, 0.5f));
        ImVec2 base_window_size(400.0f, 300.0f); /* we make sure it's scaled properly, so it won't look bad on other resolutions/sizes */
        ImGui::SetNextWindowSize(ImVec2(base_window_size.x * render.getDpi(), base_window_size.y * render.getDpi()), ImGuiCond_Once);

        /* start youinjectme gui */
        ImGui::Begin("youinjectme v1.0", &show, ImGuiWindowFlags_NoResize);
        if (ImGui::BeginTabBar("Tabs")) {
            if (ImGui::BeginTabItem("injector")) {
                if (ImGui::BeginTable("InjectorT", 1, ImGuiTableFlags_SizingStretchSame)) {
                    ImGui::TableNextColumn();
                    ImGui::BeginChild("InjectorC", ImVec2(0, 180), true);

                    ImGui::Text("you inject me");
                    ImGui::Separator();
                    ImGui::InputTextWithHint("##name", "process name", &dllName);

                    if (ImGui::Button("select dll")) {
                        injector.selectDll();
                    }

                    if (ImGui::Button("inject dll")) {
                        injector.injectDll(dllName);
                    }
                    ImGui::EndChild();
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        ImGui::End();

        render.end();
	}
	render.shutdown();
}