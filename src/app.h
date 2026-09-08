#pragma once

#include <cstdlib>
#include <cstring>

#include <rex/cvar.h>
#include <rex/filesystem.h>
#include <rex/filesystem/vfs.h>
#include <rex/logging.h>
#include <rex/rex_app.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/content_manager.h>
#include <rex/system/xam/user_profile.h>
#include <rex/system/xsocket.h>

#include "build_info.h"
#include "runtime/lobby_bridge.h"
#include "runtime/revana_hooks.h"

namespace
{

bool RevanaFlagRequested(const char* name)
{
#if defined(_WIN32)
    char*  value = nullptr;
    size_t size  = 0;
    if (_dupenv_s(&value, &size, name) != 0)
    {
        return false;
    }
    const bool enabled = value && size == 2 && value[0] == '1';
    std::free(value);
    return enabled;
#else
    const char* value = std::getenv(name);
    return value && std::strcmp(value, "1") == 0;
#endif
}

} // namespace

class RevanaApp : public rex::ReXApp
{
public:
    using rex::ReXApp::ReXApp;

    static std::unique_ptr<rex::ui::WindowedApp>
    Create(rex::ui::WindowedAppContext& ctx)
    {
        return std::unique_ptr<RevanaApp>(new RevanaApp(
            ctx, "revana", PPCImageConfig));
    }

    void OnConfigurePaths(rex::PathConfig& paths) override
    {
        const auto legacy_user_root =
            rex::filesystem::GetUserFolder() / GetName();
        if (paths.user_data_root != legacy_user_root)
        {
            return;
        }

        const auto user_root = rex::filesystem::GetUserFolder() /
                               "My Games" / "REVana360";
        if (paths.cache_root == legacy_user_root / "cache")
        {
            paths.cache_root = user_root / "cache";
        }
        paths.user_data_root = user_root;
    }

    void OnPreSetup(rex::RuntimeConfig& config) override
    {
        RevanaConfigureDirectPolUiRegistrationStub();
        REXCVAR_SET(guest_network_enabled, false);
        if (lobby_bridge_.Configure(config))
        {
            RevanaConfigureDirectPolResolver(*lobby_bridge_.configured_ipv4());
            REXCVAR_SET(guest_network_enabled, true);
        }
        RevanaSetGuestTraceHooksEnabled(
            RevanaFlagRequested("REVANA_TRACE_STARTUP"));
        config.gpu_plugin = "xenos";
    }

    void OnPostSetup() override
    {
        rex::ReXApp::OnPostSetup();
        // GetName() remains the lowercase executable identity.
        window()->SetTitle("REVana360");
    }

    void OnPostInitLogging() override
    {
        REXLOG_INFO("{}", revana::build_info::kSummary);
    }

    void OnLoadXexImage(std::string& xex_image) override
    {
        xex_image = R"(game:\PlayOnline\GameExecContent0001.xex)";
    }

    void OnPostLoadXexImage() override
    {
        auto*                                     kernel_state = runtime()->kernel_state();
        rex::system::xam::XCONTENT_AGGREGATE_DATA ffxi_content{};
        ffxi_content.device_id    = 1;
        ffxi_content.content_type = rex::system::XContentType::kPublisher;
        ffxi_content.set_file_name("R000100");
        ffxi_content.title_id = rex::system::xam::kCurrentlyRunningTitleId;
        ffxi_content.xuid     = 0;

        const auto content_result =
            kernel_state->content_manager()->RegisterExternalContent(
                kernel_state->user_profile()->xuid(), ffxi_content, game_data_root() / "0001");
        if (XFAILED(content_result))
        {
            REXLOG_ERROR(
                "Failed to register read-only 2009 FFXI content package: {:08X}",
                uint32_t(content_result));
        }

        for (const char* package_name :
             { "R000101", "R000102", "R000103", "R000104", "R000105", "R000106", "R000107", "R000108", "R000109", "R000110", "R000111" })
        {
            ffxi_content.set_file_name(package_name);
            const auto package_result =
                kernel_state->content_manager()->RegisterExternalContent(
                    kernel_state->user_profile()->xuid(), ffxi_content, game_data_root() / package_name);
            if (XFAILED(package_result))
            {
                REXLOG_ERROR(
                    "Failed to register read-only 2009 FFXI content package {}: {:08X}",
                    package_name,
                    uint32_t(package_result));
            }
            else
            {
                REXLOG_INFO("Registered read-only 2009 FFXI content package {}",
                            package_name);
            }
        }

        auto* file_system = runtime()->file_system();
        file_system->RegisterSymbolicLink(
            "100000:", R"(\Device\Harddisk0\Partition1\PlayOnline)");
        file_system->RegisterSymbolicLink(
            "NOSYS:", R"(\Device\Harddisk0\Partition1\PlayOnline)");
        file_system->RegisterSymbolicLink(
            "NOUSR:", R"(\Device\Harddisk0\Partition1\PlayOnline\user)");
        file_system->RegisterSymbolicLink("000000:",
                                          R"(\Device\Harddisk0\Partition1\0001)");
        file_system->RegisterSymbolicLink("cdrom0:",
                                          R"(\Device\Harddisk0\Partition1)");

        lobby_bridge_.StartStateTrace(runtime());
    }

    void OnShutdown() override
    {
        lobby_bridge_.StopStateTrace();
    }

private:
    RevanaLobbyBridge lobby_bridge_;
};
