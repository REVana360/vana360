#include "revana_hooks.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>

#if defined(_WIN32)
#include <windows.h>

#include <bcrypt.h>
#endif

#include <rex/logging.h>
#include <rex/system/function_dispatcher.h>
#include <rex/system/kernel_state.h>
#include <rex/system/thread_state.h>
#include <rex/system/util/object_table.h>
#include <rex/system/xobject.h>
#include <rex/system/xsocket.h>

namespace
{

std::atomic_bool         g_guest_trace_hooks_enabled              = false;
std::atomic_uint32_t     g_guest_trace_hook_count                 = 0;
std::atomic_bool         g_lobby_controller_ready                 = false;
std::atomic_uint32_t     g_lobby_controller_object                = 0;
std::atomic_bool         g_slot1852_registration_stub_enabled     = false;
std::atomic_uint32_t     g_slot1852_registration_thunk            = 0;
std::atomic_bool         g_direct_pol_resolver_enabled            = false;
std::atomic_uint32_t     g_direct_pol_resolver_ipv4               = 0;
std::atomic_uint32_t     g_direct_pol_resolver_begin_thunk        = 0;
std::atomic_uint32_t     g_direct_pol_resolver_poll_thunk         = 0;
std::atomic_uint32_t     g_direct_pol_resolver_cancel_thunk       = 0;
std::atomic_uint32_t     g_direct_pol_resolver_begin_original     = 0;
std::atomic_uint32_t     g_direct_pol_resolver_poll_original      = 0;
std::atomic_uint32_t     g_direct_pol_resolver_cancel_original    = 0;
std::atomic_uint64_t     g_config_handshake_state                 = 0;
std::atomic_uint64_t     g_config_service_state                   = 0;
std::atomic_uint64_t     g_config_parser_state                    = 0;
std::atomic_uint64_t     g_config_transfer_state                  = 0;
std::atomic_uint64_t     g_post_selection_service_open_result     = UINT64_MAX;
std::atomic_uint64_t     g_post_selection_service_poll_result     = UINT64_MAX;
std::atomic_uint64_t     g_post_selection_association_open_result = UINT64_MAX;
std::atomic_uint64_t     g_post_selection_association_poll_result = UINT64_MAX;
std::atomic_uint32_t     g_phase6_readiness_flags                 = UINT32_MAX;
std::atomic_uint64_t     g_zone_load_sequence_state               = UINT64_MAX;
std::atomic_uint64_t     g_gameplay_frame_return                  = UINT64_MAX;
std::atomic_uint64_t     g_world_network_state                    = UINT64_MAX;
std::atomic_uint32_t     g_world_status_set_count                 = 0;
std::atomic_uint32_t     g_world_error_trace_count                = 0;
std::atomic_uint32_t     g_world_dispatch_trace_count             = 0;
std::atomic_uint32_t     g_world_fatal_trace_count                = 0;
std::atomic_uint32_t     g_object_build_trace_count               = 0;
thread_local uint32_t    g_resource_load_id                       = 0;
thread_local uint32_t    g_resource_load_caller                   = 0;
std::atomic_uint32_t     g_world_receive_decode_result            = UINT32_MAX;
std::atomic_uint32_t     g_world_entity_update_trace_count        = 0;
std::atomic_uint32_t     g_world_packet_dequeue_result            = UINT32_MAX;
std::atomic_uint64_t     g_world_send_target                      = UINT64_MAX;
std::atomic_uint32_t     g_lobby_next_login_character_id          = 0;
std::atomic_bool         g_world_login_character_id_restored      = false;
std::atomic_bool         g_direct_view_bootstrap_enabled          = false;
std::atomic_bool         g_direct_view_bootstrap_sent             = false;
uint16_t                 g_direct_view_bootstrap_port             = 0;
std::array<uint8_t, 152> g_direct_view_bootstrap_packet{};
std::atomic_bool         g_direct_map_cipher_key_enabled  = false;
std::atomic_bool         g_direct_map_cipher_key_reported = false;
std::array<uint8_t, 16>  g_direct_map_cipher_key{};
std::atomic_bool         g_direct_map_endpoint_enabled = false;
std::atomic_uint32_t     g_direct_map_ipv4             = 0;
std::atomic_uint16_t     g_direct_map_port             = 0;

constexpr uint32_t kMaximumGuestTraceHooks        = 256;
constexpr uint32_t kDirectPolResolverHandle       = 0x50584901;
constexpr uint32_t kSocketMessagePeek             = 2;
constexpr uint32_t kPolResolverBeginOffset        = 884;
constexpr uint32_t kPolResolverPollOffset         = 888;
constexpr uint32_t kPolResolverCancelOffset       = 892;
constexpr uint32_t kPolResolverServiceInitializer = 0x82465908;
constexpr uint32_t kPolResolverServiceReady       = 0x824B9CBC;
constexpr uint32_t kPolSessionInitializer         = 0x82475BE8;
constexpr uint32_t kPolSessionPointer             = 0x824DCC58;
constexpr uint32_t kPolConfigCipherEnabled        = 0x824DC93B;
constexpr uint32_t kPolNetworkAvailableSetter     = 0x82471F00;
constexpr uint32_t kPolNetworkAvailable           = 0x824D9078;
constexpr char     kRetailLobbyHostname[]         = "ffxi00.pol.com";

uint16_t ReadLe16(const uint8_t* bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
           (static_cast<uint16_t>(bytes[1]) << 8);
}

uint32_t ReadLe32(const uint8_t* bytes)
{
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

bool EnvironmentFlagRequested(const char* name)
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

const bool kSynthesizePostSelectionDescriptors = EnvironmentFlagRequested(
    "REVANA_EXPERIMENTAL_POST_SELECTION_DESCRIPTORS");
const bool kSkipPostSelectionServiceFailure = EnvironmentFlagRequested(
    "REVANA_EXPERIMENTAL_SKIP_POST_SELECTION_SERVICE_FAILURE");
const bool kRestoreWorldLoginCharacterId = EnvironmentFlagRequested(
    "REVANA_EXPERIMENTAL_RESTORE_WORLD_LOGIN_CHARACTER_ID");

bool GuestTraceHooksEnabled()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return false;
    }
    const uint32_t index =
        g_guest_trace_hook_count.fetch_add(1, std::memory_order_relaxed);
    if (index < kMaximumGuestTraceHooks)
    {
        return true;
    }
    if (index == kMaximumGuestTraceHooks)
    {
        REXLOG_INFO("Xbox guest mid-asm trace reached its event limit");
    }
    return false;
}

void RevanaDirectPolUiRegistrationStub(PPCContext& ctx,
                                       uint8_t* /*base*/)
{
    REXLOG_INFO("Xbox direct-mode POL UI registration stub invoked with "
                "r3=0x{:08X}",
                ctx.r3.u32);
}

bool GuestStringEquals(uint32_t address, const char* expected)
{
    if (address == 0)
    {
        return false;
    }
    const auto* memory = rex::runtime::ThreadState::Get()->memory();
    const auto* value  = memory->TranslateVirtual<const char*>(address);
    for (size_t index = 0;; ++index)
    {
        if (value[index] != expected[index])
        {
            return false;
        }
        if (expected[index] == '\0')
        {
            return true;
        }
    }
}

void CallOriginalPolResolver(PPCContext& ctx, uint8_t* base, uint32_t original)
{
    auto* kernel_state = rex::runtime::current_kernel_state();
    auto* function =
        kernel_state ? kernel_state->function_dispatcher()->GetFunction(original)
                     : nullptr;
    if (!function)
    {
        REXLOG_ERROR("Xbox direct resolver original target is unavailable: "
                     "0x{:08X}",
                     original);
        ctx.r3.s64 = -2071;
        return;
    }
    function(ctx, base);
}

bool EnsureDirectPolNetworkState(PPCContext& ctx, uint8_t* base)
{
    auto* kernel_state = rex::runtime::current_kernel_state();
    auto* thread_state = rex::runtime::ThreadState::Get();
    if (!kernel_state || !thread_state)
    {
        REXLOG_ERROR("Xbox direct resolver has no guest runtime state");
        return false;
    }

    auto* dispatcher     = kernel_state->function_dispatcher();
    auto* memory         = thread_state->memory();
    auto  load_guest_u32 = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };

    if (load_guest_u32(kPolResolverServiceReady) == 0)
    {
        auto* initializer =
            dispatcher->GetFunction(kPolResolverServiceInitializer);
        if (!initializer)
        {
            REXLOG_ERROR("Xbox direct resolver cannot resolve the normal PolCore "
                         "resolver-service initializer");
            return false;
        }
        ctx.r3.u64 = 2;
        initializer(ctx, base);
        const uint32_t service_ready =
            load_guest_u32(kPolResolverServiceReady);
        REXLOG_INFO(
            "Xbox direct resolver invoked normal PolCore resolver-service "
            "initializer: result={} ready={}",
            ctx.r3.s32,
            service_ready);
        if (ctx.r3.s32 < 0 || service_ready == 0)
        {
            REXLOG_ERROR(
                "Xbox direct resolver PolCore resolver-service initialization failed");
            return false;
        }
    }

    if (load_guest_u32(kPolSessionPointer) == 0)
    {
        auto* initializer = dispatcher->GetFunction(kPolSessionInitializer);
        if (!initializer)
        {
            REXLOG_ERROR("Xbox direct resolver cannot resolve the normal PolCore "
                         "session initializer");
            return false;
        }
        ctx.r3.u64 = 0;
        ctx.r4.u64 = 0;
        ctx.r5.u64 = 0;
        initializer(ctx, base);
        const uint32_t session_pointer = load_guest_u32(kPolSessionPointer);
        REXLOG_INFO(
            "Xbox direct resolver invoked normal PolCore session initializer: "
            "pointer=0x{:08X}",
            session_pointer);
        if (session_pointer == 0)
        {
            REXLOG_ERROR("Xbox direct resolver PolCore session initialization failed");
            return false;
        }
    }

    // Retail POL establishes the shared cipher before GameExec reaches this
    // service. Direct mode has no POL session, so use the retail plaintext path
    // for the local configuration bridge instead of dereferencing its empty
    // cipher template.
    auto* config_cipher_enabled =
        memory->TranslateVirtual<uint8_t*>(kPolConfigCipherEnabled);
    if (*config_cipher_enabled != 0)
    {
        *config_cipher_enabled = 0;
        REXLOG_INFO("Xbox direct resolver selected plaintext configuration "
                    "transport");
    }

    if (load_guest_u32(kPolNetworkAvailable) == 0)
    {
        auto* setter = dispatcher->GetFunction(kPolNetworkAvailableSetter);
        if (!setter)
        {
            REXLOG_ERROR("Xbox direct resolver cannot resolve the normal PolCore "
                         "network-available setter");
            return false;
        }
        setter(ctx, base);
        const uint32_t network_available = load_guest_u32(kPolNetworkAvailable);
        REXLOG_INFO(
            "Xbox direct resolver invoked normal PolCore network-available "
            "setter: value={}",
            network_available);
        if (network_available == 0)
        {
            REXLOG_ERROR("Xbox direct resolver PolCore network initialization failed");
            return false;
        }
    }
    return true;
}

void RevanaDirectPolResolverBegin(PPCContext& ctx, uint8_t* base)
{
    if (!GuestStringEquals(ctx.r3.u32, kRetailLobbyHostname))
    {
        CallOriginalPolResolver(
            ctx, base, g_direct_pol_resolver_begin_original.load(std::memory_order_relaxed));
        return;
    }
    if (!EnsureDirectPolNetworkState(ctx, base))
    {
        ctx.r3.s64 = -2071;
        return;
    }
    ctx.r3.u64 = kDirectPolResolverHandle;
    REXLOG_INFO("Xbox direct resolver accepted retail lobby hostname");
}

void RevanaDirectPolResolverPoll(PPCContext& ctx, uint8_t* base)
{
    if (ctx.r3.u32 != kDirectPolResolverHandle)
    {
        CallOriginalPolResolver(
            ctx, base, g_direct_pol_resolver_poll_original.load(std::memory_order_relaxed));
        return;
    }
    if (ctx.r4.u32 == 0)
    {
        ctx.r3.s64 = -22;
        return;
    }

    auto* memory = rex::runtime::ThreadState::Get()->memory();
    std::memset(memory->TranslateVirtual(ctx.r4.u32), 0, 20);
    rex::memory::store_and_swap<uint32_t>(
        memory->TranslateVirtual(ctx.r4.u32 + 4),
        g_direct_pol_resolver_ipv4.load(std::memory_order_relaxed));
    ctx.r3.s64 = 1;
    REXLOG_INFO("Xbox direct resolver returned configured lobby IPv4 address");
}

void RevanaDirectPolResolverCancel(PPCContext& ctx, uint8_t* base)
{
    if (ctx.r3.u32 != kDirectPolResolverHandle)
    {
        CallOriginalPolResolver(
            ctx, base, g_direct_pol_resolver_cancel_original.load(std::memory_order_relaxed));
        return;
    }
    ctx.r3.s64 = 0;
    REXLOG_INFO("Xbox direct resolver released synthetic request");
}

bool InstallDirectPolResolver(uint32_t table)
{
    if (!g_direct_pol_resolver_enabled.load(std::memory_order_relaxed))
    {
        return false;
    }

    auto* kernel_state = rex::runtime::current_kernel_state();
    if (!kernel_state)
    {
        REXLOG_ERROR("Xbox direct resolver has no kernel");
        return false;
    }
    auto*      dispatcher = kernel_state->function_dispatcher();
    auto*      memory     = rex::runtime::ThreadState::Get()->memory();
    const auto load_entry = [memory, table](uint32_t offset)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(table + offset));
    };
    const auto store_entry = [memory, table](uint32_t offset, uint32_t target)
    {
        rex::memory::store_and_swap<uint32_t>(
            memory->TranslateVirtual(table + offset), target);
    };

    const uint32_t installed_begin =
        g_direct_pol_resolver_begin_thunk.load(std::memory_order_relaxed);
    if (installed_begin != 0 &&
        load_entry(kPolResolverBeginOffset) == installed_begin)
    {
        return true;
    }

    const uint32_t begin_original  = load_entry(kPolResolverBeginOffset);
    const uint32_t poll_original   = load_entry(kPolResolverPollOffset);
    const uint32_t cancel_original = load_entry(kPolResolverCancelOffset);
    if (begin_original == 0 || poll_original == 0 || cancel_original == 0)
    {
        REXLOG_ERROR(
            "Xbox direct resolver found incomplete service slots: "
            "+884=0x{:08X} +888=0x{:08X} +892=0x{:08X}",
            begin_original,
            poll_original,
            cancel_original);
        return false;
    }

    const uint32_t begin_thunk = dispatcher->AllocateThunk(
        RevanaDirectPolResolverBegin, 0x8418880C);
    const uint32_t poll_thunk = dispatcher->AllocateThunk(
        RevanaDirectPolResolverPoll, 0x84188858);
    const uint32_t cancel_thunk = dispatcher->AllocateThunk(
        RevanaDirectPolResolverCancel, 0x84188858);
    if (begin_thunk == 0 || poll_thunk == 0 || cancel_thunk == 0)
    {
        REXLOG_ERROR("Xbox direct resolver thunk allocation failed");
        return false;
    }

    g_direct_pol_resolver_begin_original.store(begin_original,
                                               std::memory_order_relaxed);
    g_direct_pol_resolver_poll_original.store(poll_original,
                                              std::memory_order_relaxed);
    g_direct_pol_resolver_cancel_original.store(cancel_original,
                                                std::memory_order_relaxed);
    g_direct_pol_resolver_begin_thunk.store(begin_thunk,
                                            std::memory_order_relaxed);
    g_direct_pol_resolver_poll_thunk.store(poll_thunk,
                                           std::memory_order_relaxed);
    g_direct_pol_resolver_cancel_thunk.store(cancel_thunk,
                                             std::memory_order_relaxed);
    store_entry(kPolResolverBeginOffset, begin_thunk);
    store_entry(kPolResolverPollOffset, poll_thunk);
    store_entry(kPolResolverCancelOffset, cancel_thunk);
    REXLOG_INFO(
        "Xbox direct resolver installed over service slots +884/+888/+892 "
        "originals=0x{:08X},0x{:08X},0x{:08X}",
        begin_original,
        poll_original,
        cancel_original);
    return true;
}

uint32_t InstallDirectPolUiRegistrationStub(uint32_t table)
{
    if (!g_slot1852_registration_stub_enabled.load(std::memory_order_relaxed))
    {
        return 0;
    }
    uint32_t thunk =
        g_slot1852_registration_thunk.load(std::memory_order_relaxed);
    if (thunk == 0)
    {
        auto* kernel_state = rex::runtime::current_kernel_state();
        if (!kernel_state)
        {
            REXLOG_ERROR("Xbox direct-mode POL UI registration stub has no kernel");
            return 0;
        }
        thunk = kernel_state->function_dispatcher()->AllocateThunk(
            RevanaDirectPolUiRegistrationStub, 0x8421CBD8);
        if (thunk == 0)
        {
            REXLOG_ERROR("Xbox direct-mode POL UI registration stub allocation "
                         "failed");
            return 0;
        }
        g_slot1852_registration_thunk.store(thunk, std::memory_order_relaxed);
    }

    auto* memory = rex::runtime::ThreadState::Get()->memory();
    rex::memory::store_and_swap<uint32_t>(memory->TranslateVirtual(table + 1852),
                                          thunk);
    REXLOG_INFO("Xbox direct-mode POL UI registration stub installed at "
                "0x{:08X}",
                thunk);
    return thunk;
}

} // namespace

void RevanaSetGuestTraceHooksEnabled(bool enabled)
{
    if (enabled)
    {
        g_guest_trace_hook_count.store(0, std::memory_order_relaxed);
        g_lobby_controller_ready.store(false, std::memory_order_relaxed);
        g_lobby_controller_object.store(0, std::memory_order_relaxed);
        g_world_status_set_count.store(0, std::memory_order_relaxed);
        g_world_error_trace_count.store(0, std::memory_order_relaxed);
        g_world_dispatch_trace_count.store(0, std::memory_order_relaxed);
        g_world_fatal_trace_count.store(0, std::memory_order_relaxed);
        g_object_build_trace_count.store(0, std::memory_order_relaxed);
        g_world_send_target.store(UINT64_MAX, std::memory_order_relaxed);
    }
    g_guest_trace_hooks_enabled.store(enabled, std::memory_order_relaxed);
    if (enabled)
    {
        REXLOG_INFO("Xbox guest mid-asm trace enabled");
    }
}

bool RevanaGuestLobbyControllerReady()
{
    return g_lobby_controller_ready.load(std::memory_order_acquire);
}

uint32_t RevanaGuestLobbyControllerObject()
{
    return g_lobby_controller_object.load(std::memory_order_acquire);
}

void RevanaConfigureDirectPolUiRegistrationStub()
{
    g_slot1852_registration_thunk.store(0, std::memory_order_relaxed);
    g_slot1852_registration_stub_enabled.store(true,
                                               std::memory_order_relaxed);
    REXLOG_INFO("Xbox direct-mode POL UI registration fallback enabled");
}

void RevanaConfigureDirectPolResolver(uint32_t ipv4_address)
{
    g_direct_pol_resolver_ipv4.store(ipv4_address, std::memory_order_relaxed);
    g_direct_pol_resolver_enabled.store(true, std::memory_order_relaxed);
    REXLOG_INFO("Xbox direct resolver fallback enabled");
}

void RevanaTraceNetworkInitEntry()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox network initializer entered");
    }
}

void RevanaTraceNetworkInitFatalConfig()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox network initializer selected fatal configuration path");
    }
}

void RevanaTraceNetworkInitBeforeWsa()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox network initializer reached WSA handoff");
    }
}

void RevanaTraceServiceDispatchSlot1852()
{
    const bool trace_enabled =
        g_guest_trace_hooks_enabled.load(std::memory_order_relaxed);
    const bool stub_enabled =
        g_slot1852_registration_stub_enabled.load(std::memory_order_relaxed);
    const bool resolver_enabled =
        g_direct_pol_resolver_enabled.load(std::memory_order_relaxed);
    if (!trace_enabled && !stub_enabled && !resolver_enabled)
    {
        return;
    }

    auto* ctx = rex::runtime::current_ppc_context();
    if (trace_enabled)
    {
        const auto* memory     = rex::runtime::ThreadState::Get()->memory();
        const auto  load_entry = [memory, table = ctx->r11.u32](uint32_t offset)
        {
            return rex::memory::load_and_swap<uint32_t>(
                memory->TranslateVirtual<const uint32_t*>(table + offset));
        };
        uint32_t populated_entries       = 0;
        uint32_t previous_offset         = 0;
        uint32_t previous_target         = 0;
        uint32_t next_offset             = 0;
        uint32_t next_target             = 0;
        uint32_t outside_polcore_entries = 0;
        for (uint32_t offset = 0; offset <= 4284; offset += 4)
        {
            const uint32_t target = load_entry(offset);
            if (target == 0)
            {
                continue;
            }
            ++populated_entries;
            if (target < 0x82400000 || target >= 0x82540000)
            {
                ++outside_polcore_entries;
                REXLOG_INFO(
                    "Xbox service dispatch outside PolCore +{}=0x{:08X}", offset, target);
            }
            if (offset < 1852)
            {
                previous_offset = offset;
                previous_target = target;
            }
            else if (offset > 1852 && next_target == 0)
            {
                next_offset = offset;
                next_target = target;
            }
        }
        REXLOG_INFO(
            "Xbox service dispatch table=0x{:08X} entries +1840..+1864="
            "{:08X},{:08X},{:08X},{:08X},{:08X},{:08X},{:08X}",
            ctx->r11.u32,
            load_entry(1840),
            load_entry(1844),
            load_entry(1848),
            load_entry(1852),
            load_entry(1856),
            load_entry(1860),
            load_entry(1864));
        REXLOG_INFO(
            "Xbox service dispatch populated={} nearest to +1852: "
            "+{}=0x{:08X}, +{}=0x{:08X}",
            populated_entries,
            previous_offset,
            previous_target,
            next_offset,
            next_target);
        REXLOG_INFO("Xbox service dispatch outside PolCore entries={}",
                    outside_polcore_entries);
        REXLOG_INFO(
            "Xbox service dispatch +1852 constructor call argument=0x{:08X} "
            "target=0x{:08X}",
            ctx->r3.u32,
            ctx->r10.u32);
    }
    if (resolver_enabled)
    {
        InstallDirectPolResolver(ctx->r11.u32);
    }
    if (ctx->r10.u32 == 0 && stub_enabled)
    {
        const uint32_t thunk = InstallDirectPolUiRegistrationStub(ctx->r11.u32);
        if (thunk != 0)
        {
            ctx->r10.u64 = thunk;
        }
    }
}

void RevanaTraceServiceDispatchSlot1852Object()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        REXLOG_INFO("Xbox service dispatch +1852 object call argument=0x{:08X} "
                    "table=0x{:08X} target=0x{:08X}",
                    ctx->r3.u32,
                    ctx->r11.u32,
                    ctx->r8.u32);
    }
}

void RevanaTraceType2Enqueue()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        if (ctx->r4.u32 != 8 || ctx->r5.u32 != 2)
        {
            return;
        }
        const auto* memory    = rex::runtime::ThreadState::Get()->memory();
        const auto  load_word = [memory](uint32_t address)
        {
            return rex::memory::load_and_swap<uint32_t>(
                memory->TranslateVirtual<const uint32_t*>(address));
        };
        REXLOG_INFO(
            "Xbox eight-word enqueue lr=0x{:08X} owner=0x{:08X} "
            "type={} payload={:08X},{:08X},{:08X},{:08X},{:08X},{:08X},{:08X}",
            ctx->lr,
            ctx->r3.u32,
            ctx->r5.u32,
            ctx->r6.u32,
            ctx->r7.u32,
            ctx->r8.u32,
            ctx->r9.u32,
            ctx->r10.u32,
            load_word(ctx->r1.u32 + 84),
            load_word(ctx->r1.u32 + 92));
        REXLOG_INFO(
            "Xbox eight-word enqueue read state handle=0x{:08X} bytes={} "
            "buffer_words={:08X},{:08X}",
            load_word(ctx->r1.u32 + 160),
            load_word(ctx->r1.u32 + 164),
            load_word(ctx->r6.u32),
            load_word(ctx->r6.u32 + 4));
    }
}

void RevanaTraceType2ReadReturned()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx       = rex::runtime::current_ppc_context();
        const auto* memory    = rex::runtime::ThreadState::Get()->memory();
        const auto  load_word = [memory](uint32_t address)
        {
            return rex::memory::load_and_swap<uint32_t>(
                memory->TranslateVirtual<const uint32_t*>(address));
        };
        REXLOG_INFO(
            "Xbox type 2 read returned result={} handle=0x{:08X} bytes={} "
            "buffer=0x{:08X} words={:08X},{:08X} requested={}",
            ctx->r3.u32,
            load_word(ctx->r1.u32 + 160),
            load_word(ctx->r1.u32 + 164),
            ctx->r30.u32,
            load_word(ctx->r30.u32),
            load_word(ctx->r30.u32 + 4),
            ctx->r27.u32);
    }
}

void RevanaTraceType2ConsumerEntry()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx       = rex::runtime::current_ppc_context();
        const auto* memory    = rex::runtime::ThreadState::Get()->memory();
        const auto  load_word = [memory](uint32_t address)
        {
            return address == 0
                       ? 0
                       : rex::memory::load_and_swap<uint32_t>(
                             memory->TranslateVirtual<const uint32_t*>(address));
        };
        REXLOG_INFO(
            "Xbox type 2 consumer entry lr=0x{:08X} r3=0x{:08X} "
            "r4=0x{:08X} message_type={}",
            ctx->lr,
            ctx->r3.u32,
            ctx->r4.u32,
            load_word(ctx->r4.u32 - 4));
        REXLOG_INFO(
            "Xbox type 2 consumer input words "
            "[0]={:08X} [4]={:08X} [8]={:08X} [12]={:08X} "
            "[16]={:08X} [20]={:08X} [24]={:08X}",
            load_word(ctx->r4.u32),
            load_word(ctx->r4.u32 + 4),
            load_word(ctx->r4.u32 + 8),
            load_word(ctx->r4.u32 + 12),
            load_word(ctx->r4.u32 + 16),
            load_word(ctx->r4.u32 + 20),
            load_word(ctx->r4.u32 + 24));
        REXLOG_INFO(
            "Xbox type 2 consumer callbacks "
            "[1]={:08X} [2]={:08X} [3]={:08X} [4]={:08X} "
            "[5]={:08X} [6]={:08X}",
            load_word(0x847309FC),
            load_word(0x84730A00),
            load_word(0x84730A04),
            load_word(0x84730A08),
            load_word(0x84730A0C),
            load_word(0x84730A10));
    }
}

void RevanaTraceType2ConsumerTagRead()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx       = rex::runtime::current_ppc_context();
        const auto* memory    = rex::runtime::ThreadState::Get()->memory();
        const auto  load_word = [memory](uint32_t address)
        {
            return address == 0
                       ? 0
                       : rex::memory::load_and_swap<uint32_t>(
                             memory->TranslateVirtual<const uint32_t*>(address));
        };
        const uint32_t candidate = load_word(ctx->r31.u32 + 12);
        REXLOG_INFO("Xbox type 2 consumer read r22=0x{:08X} "
                    "r26=0x{:08X} r28=0x{:08X} r30=0x{:08X} r31=0x{:08X}",
                    ctx->r22.u32,
                    ctx->r26.u32,
                    ctx->r28.u32,
                    ctx->r30.u32,
                    ctx->r31.u32);
        REXLOG_INFO("Xbox type 2 consumer tags input={:08X} "
                    "candidate=0x{:08X}/{:08X} expected={:08X},{:08X}",
                    load_word(ctx->r30.u32),
                    candidate,
                    load_word(candidate),
                    load_word(0x8402A510),
                    load_word(0x8402A518));
    }
}

void RevanaTraceNetworkInitFailure()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox network initializer returned failure");
    }
}

void RevanaTraceNetworkInitSuccess()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox network initializer returned success");
    }
}

void RevanaTraceLobbySetupEntry()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox lobby setup entered");
    }
}

void RevanaTraceLobbySetupGuardAccepted()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox lobby setup initialization guard accepted");
    }
}

void RevanaTraceLobbySetupFailure()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox lobby setup returned failure");
    }
}

void RevanaTraceLobbyControllerEntry()
{
    const auto* ctx = rex::runtime::current_ppc_context();
    g_lobby_controller_object.store(ctx->r3.u32, std::memory_order_relaxed);
    g_lobby_controller_ready.store(true, std::memory_order_release);
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox lobby controller initialization entered");
    }
}

bool CalculateMd5(const uint8_t* bytes, size_t size, uint8_t* digest)
{
#if defined(_WIN32)
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_MD5_ALGORITHM, nullptr, 0)))
    {
        return false;
    }

    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS           status =
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    if (BCRYPT_SUCCESS(status))
    {
        status = BCryptHashData(hash, const_cast<uint8_t*>(bytes), static_cast<ULONG>(size), 0);
    }
    if (BCRYPT_SUCCESS(status))
    {
        status = BCryptFinishHash(hash, digest, 16, 0);
    }
    if (hash != nullptr)
    {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return BCRYPT_SUCCESS(status);
#else
    return false;
#endif
}

bool RestoreWorldLoginCharacterId(uint8_t* packet, size_t packet_size)
{
    constexpr size_t kOuterHeaderSize  = 28;
    constexpr size_t kLoginPacketSize  = 92;
    constexpr size_t kOuterDigestSize  = 16;
    constexpr size_t kLoginCheckOffset = kOuterHeaderSize + 4;
    constexpr size_t kUniqueNoOffset   = kOuterHeaderSize + 12;
    constexpr size_t kLoginCheckStart  = kOuterHeaderSize + 8;
    if (packet_size < kOuterHeaderSize + kLoginPacketSize + kOuterDigestSize ||
        (ReadLe32(packet + kOuterHeaderSize) & 0x1FF) != 0x0A)
    {
        return false;
    }
    const size_t outer_digest_offset = packet_size - kOuterDigestSize;

    const uint32_t full_id =
        g_lobby_next_login_character_id.load(std::memory_order_acquire);
    const uint32_t packet_id = ReadLe32(packet + kUniqueNoOffset);
    if (full_id == 0 || packet_id == full_id ||
        (packet_id & 0x00FFFFFF) != (full_id & 0x00FFFFFF))
    {
        return false;
    }

    const uint8_t original_login_check = packet[kLoginCheckOffset];
    packet[kUniqueNoOffset]            = static_cast<uint8_t>(full_id);
    packet[kUniqueNoOffset + 1]        = static_cast<uint8_t>(full_id >> 8);
    packet[kUniqueNoOffset + 2]        = static_cast<uint8_t>(full_id >> 16);
    packet[kUniqueNoOffset + 3]        = static_cast<uint8_t>(full_id >> 24);

    uint8_t login_check = 0;
    for (size_t offset = kLoginCheckStart;
         offset < kOuterHeaderSize + kLoginPacketSize;
         ++offset)
    {
        login_check = static_cast<uint8_t>(login_check + packet[offset]);
    }
    packet[kLoginCheckOffset] = login_check;
    std::array<uint8_t, 16> outer_digest{};
    if (!CalculateMd5(packet + kOuterHeaderSize,
                      outer_digest_offset - kOuterHeaderSize,
                      outer_digest.data()))
    {
        packet[kUniqueNoOffset]     = static_cast<uint8_t>(packet_id);
        packet[kUniqueNoOffset + 1] = static_cast<uint8_t>(packet_id >> 8);
        packet[kUniqueNoOffset + 2] = static_cast<uint8_t>(packet_id >> 16);
        packet[kUniqueNoOffset + 3] = static_cast<uint8_t>(packet_id >> 24);
        packet[kLoginCheckOffset]   = original_login_check;
        return false;
    }
    std::copy(outer_digest.begin(), outer_digest.end(), packet + outer_digest_offset);

    if (!g_world_login_character_id_restored.exchange(
            true, std::memory_order_relaxed))
    {
        REXLOG_WARN(
            "Experimental direct mode restored world-login character ID "
            "from 0x{:08X} to 0x{:08X}",
            packet_id,
            full_id);
    }
    return true;
}

void RevanaTraceLobbyCommand31Poll()
{
    auto*       ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    const int32_t queue_result = ctx->r3.s32;
    const int32_t connection_state =
        static_cast<int32_t>(load_word(ctx->r30.u32));
    if (queue_result < 0 && connection_state != 6)
    {
        return;
    }
    if (!GuestTraceHooksEnabled())
    {
        return;
    }
    const uint32_t packet =
        queue_result >= 0 ? load_word(ctx->r1.u32 + 80) : 0;
    REXLOG_INFO(
        "Xbox lobby command 0x1F poll result={} connection_state={} "
        "transaction_state={} packet=0x{:08X}",
        queue_result,
        connection_state,
        load_word(ctx->r28.u32),
        packet);
}

void RevanaTraceLobbyCommand31Packet()
{
    if (!GuestTraceHooksEnabled())
    {
        return;
    }
    auto*       ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    REXLOG_INFO(
        "Xbox lobby command 0x1F response type={} packet=0x{:08X} "
        "packet_error={}",
        ctx->r3.u32,
        ctx->r27.u32,
        static_cast<int32_t>(load_word(ctx->r27.u32 + 32)));
}

void RevanaTraceZoneDescriptorLookup()
{
    if (!GuestTraceHooksEnabled())
    {
        return;
    }

    constexpr uint32_t kFfxiStatePointer             = 0x847A12F8;
    constexpr uint32_t kPolServiceTable              = 0x82524210;
    constexpr uint32_t kPolConnectionTable           = 0x824DFAF0;
    constexpr uint32_t kPolConnectionSize            = 104;
    constexpr uint32_t kPolConnectionCount           = 64;
    constexpr uint32_t kPolLocalEndpointTable        = 0x824DD650;
    constexpr uint32_t kDescriptorIdentifierOffset   = 65536 + 11988;
    constexpr uint32_t kDescriptorEndpointHighOffset = 65536 + 11992;
    constexpr uint32_t kDescriptorEndpointLowOffset  = 65536 + 11994;
    constexpr uint32_t kDescriptorEndpointByteOffset = 65536 + 11999;

    auto*       ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    const auto load_half = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint16_t>(
            memory->TranslateVirtual<const uint16_t*>(address));
    };
    const auto load_double = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint64_t>(
            memory->TranslateVirtual<const uint64_t*>(address));
    };
    const auto store_half = [memory](uint32_t address, uint16_t value)
    {
        rex::memory::store_and_swap<uint16_t>(memory->TranslateVirtual(address),
                                              value);
    };
    const auto store_word = [memory](uint32_t address, uint32_t value)
    {
        rex::memory::store_and_swap<uint32_t>(memory->TranslateVirtual(address),
                                              value);
    };
    const auto store_double = [memory](uint32_t address, uint64_t value)
    {
        rex::memory::store_and_swap<uint64_t>(memory->TranslateVirtual(address),
                                              value);
    };

    const uint32_t state    = load_word(kFfxiStatePointer);
    const uint32_t selected = ctx->r29.u32;
    if (state == 0 || selected >= 16)
    {
        REXLOG_INFO(
            "Xbox post-selection descriptor lookup result={} selected={} "
            "state=0x{:08X}",
            ctx->r3.s32,
            selected,
            state);
        return;
    }

    const uint32_t record       = state + selected * 140;
    uint32_t       active_count = 0;
    uint32_t       first_active = kPolConnectionCount;
    for (uint32_t index = 0; index < kPolConnectionCount; ++index)
    {
        const uint32_t connection =
            kPolConnectionTable + index * kPolConnectionSize;
        if ((load_half(connection) & 1) != 0)
        {
            ++active_count;
            if (first_active == kPolConnectionCount)
            {
                first_active = index;
            }
        }
    }
    const uint32_t first_connection =
        kPolConnectionTable + first_active * kPolConnectionSize;
    const uint32_t identifier =
        load_word(record + kDescriptorIdentifierOffset);
    const uint16_t endpoint_high =
        load_half(record + kDescriptorEndpointHighOffset);
    const uint16_t endpoint_low =
        load_half(record + kDescriptorEndpointLowOffset);
    const uint8_t endpoint_byte = *memory->TranslateVirtual<const uint8_t*>(
        record + kDescriptorEndpointByteOffset);
    bool synthesized = false;
    if (ctx->r3.s32 < 0 && active_count == 0 &&
        kSynthesizePostSelectionDescriptors)
    {
        const uint32_t combined =
            (static_cast<uint32_t>(endpoint_byte) << 16) + endpoint_high;
        const uint32_t intermediate =
            (std::rotl(static_cast<uint32_t>(endpoint_low), 8) & 0x00FFFF00) |
            (combined & 0xFFFF0000);
        const uint32_t endpoint =
            (std::rotl(intermediate, 8) & 0xFFFFFF00) |
            (combined & 0xFFFF);
        store_half(kPolConnectionTable, 1);
        store_half(kPolConnectionTable + 2, 1);
        store_word(kPolConnectionTable + 4, endpoint);
        store_double(kPolConnectionTable + 8, identifier);
        store_double(kPolConnectionTable + 16, 0);
        store_double(kPolLocalEndpointTable, 1);
        ctx->r3.s64 = 0;
        synthesized = true;
        REXLOG_WARN(
            "Experimental post-selection remote and local descriptors "
            "synthesized: "
            "endpoint=0x{:08X} identifier=0x{:08X}",
            endpoint,
            identifier);
    }
    REXLOG_INFO(
        "Xbox post-selection descriptor lookup result={} selected={} "
        "identifier_key=0x{:08X} endpoint_high=0x{:04X} "
        "endpoint_low={} endpoint_byte=0x{:02X} "
        "service708=0x{:08X} active={} first={} flags=0x{:04X} "
        "type={} endpoint=0x{:08X} identifier=0x{:016X} token=0x{:016X} "
        "synthesized={}",
        ctx->r3.s32,
        selected,
        identifier,
        endpoint_high,
        endpoint_low,
        endpoint_byte,
        load_word(kPolServiceTable + 708),
        active_count,
        first_active,
        first_active < kPolConnectionCount ? load_half(first_connection) : 0,
        first_active < kPolConnectionCount
            ? load_half(first_connection + 2)
            : 0,
        first_active < kPolConnectionCount
            ? load_word(first_connection + 4)
            : 0,
        first_active < kPolConnectionCount
            ? load_double(first_connection + 8)
            : 0,
        first_active < kPolConnectionCount
            ? load_double(first_connection + 16)
            : 0,
        synthesized);
}

void TracePostSelectionServiceReturn(const char*           operation,
                                     std::atomic_uint64_t& observed_result)
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }

    constexpr uint32_t kFfxiDataPointer           = 0x847A12F8;
    constexpr uint32_t kPostSelectionHandleOffset = 65536 + 11576;
    const auto*        ctx                        = rex::runtime::current_ppc_context();
    const auto*        memory                     = rex::runtime::ThreadState::Get()->memory();
    const auto         load_word                  = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };

    const uint32_t flow  = ctx->r27.u32;
    const uint32_t data  = load_word(kFfxiDataPointer);
    const uint32_t state = flow != 0 ? load_word(flow) : UINT32_MAX;
    const uint32_t stored_handle =
        data != 0 ? load_word(data + kPostSelectionHandleOffset) : 0;
    const uint64_t observation =
        (static_cast<uint64_t>(state) << 32) | ctx->r3.u32;
    if (observed_result.exchange(observation, std::memory_order_relaxed) ==
        observation)
    {
        return;
    }
    REXLOG_INFO(
        "Xbox post-selection {} return={} state={} stored_handle=0x{:08X} "
        "r3=0x{:08X} r4=0x{:08X} r29=0x{:08X}",
        operation,
        ctx->r3.s32,
        state,
        stored_handle,
        ctx->r3.u32,
        ctx->r4.u32,
        ctx->r29.u32);
}

void RevanaTracePostSelectionServiceOpen()
{
    TracePostSelectionServiceReturn("service open",
                                    g_post_selection_service_open_result);
}

void RevanaTracePostSelectionServicePoll()
{
    TracePostSelectionServiceReturn("service poll",
                                    g_post_selection_service_poll_result);
    auto* ctx = rex::runtime::current_ppc_context();
    if (ctx->r3.s32 < 0 && kSkipPostSelectionServiceFailure)
    {
        REXLOG_WARN(
            "Experimental direct mode translated obsolete post-selection "
            "service failure {} to completion",
            ctx->r3.s32);
        ctx->r3.s64 = 1;
    }
}

void RevanaTracePostSelectionAssociationOpen()
{
    TracePostSelectionServiceReturn("association open",
                                    g_post_selection_association_open_result);
}

void RevanaTracePostSelectionAssociationPoll()
{
    TracePostSelectionServiceReturn("association poll",
                                    g_post_selection_association_poll_result);
}

void RevanaTracePhase6Readiness()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto*    ctx   = rex::runtime::current_ppc_context();
    const uint32_t flags = ctx->r3.u32;
    const uint32_t previous =
        g_phase6_readiness_flags.exchange(flags, std::memory_order_relaxed);
    if (previous != flags)
    {
        REXLOG_INFO("Xbox phase 6 readiness flags=0x{:08X} ready={}", flags, flags & 1);
    }
}

void RevanaTraceZoneLoadSequence()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto*    ctx    = rex::runtime::current_ppc_context();
    const auto*    memory = rex::runtime::ThreadState::Get()->memory();
    const uint32_t object = ctx->r3.u32;
    const uint16_t phase  = rex::memory::load_and_swap<uint16_t>(
        memory->TranslateVirtual<const uint16_t*>(object + 4));
    const uint16_t detail = rex::memory::load_and_swap<uint16_t>(
        memory->TranslateVirtual<const uint16_t*>(object + 6));
    const uint64_t observation =
        (static_cast<uint64_t>(object) << 32) |
        (static_cast<uint64_t>(phase) << 16) | detail;
    if (g_zone_load_sequence_state.exchange(observation,
                                            std::memory_order_relaxed) ==
        observation)
    {
        return;
    }
    REXLOG_INFO(
        "Xbox zone-load sequence: object=0x{:08X} phase={} detail={}", object, phase, detail);
}

void RevanaTraceGameplayFrameReturn()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto*    ctx    = rex::runtime::current_ppc_context();
    const auto*    memory = rex::runtime::ThreadState::Get()->memory();
    const uint32_t object = ctx->r30.u32;
    const uint16_t phase  = rex::memory::load_and_swap<uint16_t>(
        memory->TranslateVirtual<const uint16_t*>(object + 4));
    const uint32_t state = rex::memory::load_and_swap<uint32_t>(
        memory->TranslateVirtual<const uint32_t*>(object + 60));
    const uint64_t observation =
        (static_cast<uint64_t>(state) << 32) |
        (static_cast<uint64_t>(phase) << 16) | ctx->r3.u16;
    if (g_gameplay_frame_return.exchange(observation,
                                         std::memory_order_relaxed) ==
        observation)
    {
        return;
    }
    REXLOG_INFO("Xbox gameplay frame return={} state={} phase={}", ctx->r3.s32, state, phase);
}

void RevanaTraceWorldNetworkUpdate()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_half = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint16_t>(
            memory->TranslateVirtual<const uint16_t*>(address));
    };
    const uint32_t object      = ctx->r3.u32;
    const uint8_t  state       = *memory->TranslateVirtual<const uint8_t*>(object + 12);
    const uint64_t observation = (static_cast<uint64_t>(object) << 32) | state;
    if (g_world_network_state.exchange(observation,
                                       std::memory_order_relaxed) ==
        observation)
    {
        return;
    }
    REXLOG_INFO(
        "Xbox world network update: object=0x{:08X} state={} sequence={} "
        "acknowledged={}",
        object,
        state,
        load_half(object + 6),
        load_half(object + 10));
}

void RevanaApplyDirectMapCipherKey()
{
    if (!g_direct_map_cipher_key_enabled.load(std::memory_order_acquire))
    {
        return;
    }

    auto* ctx = rex::runtime::current_ppc_context();
    if (ctx->r7.u32 == 0)
    {
        return;
    }
    auto* memory = rex::runtime::ThreadState::Get()->memory();
    auto* destination =
        memory->TranslateVirtual<uint8_t*>(ctx->r7.u32);
    std::copy(g_direct_map_cipher_key.begin(), g_direct_map_cipher_key.end(), destination);
    if (!g_direct_map_cipher_key_reported.exchange(true,
                                                   std::memory_order_relaxed))
    {
        REXLOG_INFO("Xbox direct map cipher key installed at guest handoff");
    }
}

void RevanaTraceWorldReceiveDecodeResult()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    auto* ctx = rex::runtime::current_ppc_context();
    if (g_world_receive_decode_result.exchange(ctx->r3.u32,
                                               std::memory_order_relaxed) ==
        ctx->r3.u32)
    {
        return;
    }
    const auto*    memory = rex::runtime::ThreadState::Get()->memory();
    const uint32_t packet_size =
        ctx->r30.u32 == 0
            ? 0
            : rex::memory::load_and_swap<uint32_t>(
                  memory->TranslateVirtual<const uint32_t*>(ctx->r30.u32));
    REXLOG_INFO("Xbox world receive decode result={} datagram_size={}",
                ctx->r3.s32,
                packet_size);
    if (ctx->r3.s32 <= 0 || ctx->r3.u32 > 10000)
    {
        return;
    }

    const auto* plaintext =
        memory->TranslateVirtual<const uint8_t*>(ctx->r1.u32 + 864);
    constexpr uint32_t kMapTransportHeaderSize = 28;
    uint32_t           offset                  = kMapTransportHeaderSize;
    uint32_t           packet_count            = 0;
    while (offset + 4 <= ctx->r3.u32 && packet_count < 64)
    {
        const uint16_t header = static_cast<uint16_t>(plaintext[offset]) |
                                static_cast<uint16_t>(plaintext[offset + 1] << 8);
        const uint16_t id     = header & 0x1FF;
        const uint32_t size   = 2U * (plaintext[offset + 1] & 0xFE);
        if (size < 4 || offset + size > ctx->r3.u32)
        {
            REXLOG_INFO(
                "Xbox world receive packet parse stopped: offset={} id=0x{:03X} "
                "size={} total={}",
                offset,
                id,
                size,
                ctx->r3.u32);
            break;
        }
        REXLOG_INFO("Xbox world receive packet: offset={} id=0x{:03X} size={}",
                    offset,
                    id,
                    size);
        if (id == 0x00A && size >= 32)
        {
            REXLOG_INFO("Xbox world login response: hpp={} status={}",
                        plaintext[offset + 30],
                        plaintext[offset + 31]);
        }
        if (id == 0x00E && size >= 52 &&
            g_world_entity_update_trace_count.fetch_add(
                1, std::memory_order_relaxed) < 256)
        {
            const auto* packet = plaintext + offset;
            REXLOG_INFO(
                "Xbox world entity update: entity=0x{:08X} targid=0x{:04X} "
                "mask=0x{:02X} model16={} model32=0x{:08X} "
                "look={:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} "
                "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} "
                "{:02X}",
                ReadLe32(packet + 4),
                ReadLe16(packet + 8),
                packet[10],
                ReadLe16(packet + 48),
                ReadLe32(packet + 48),
                packet[48],
                packet[49],
                packet[50],
                packet[51],
                size > 52 ? packet[52] : 0,
                size > 53 ? packet[53] : 0,
                size > 54 ? packet[54] : 0,
                size > 55 ? packet[55] : 0,
                size > 56 ? packet[56] : 0,
                size > 57 ? packet[57] : 0,
                size > 58 ? packet[58] : 0,
                size > 59 ? packet[59] : 0,
                size > 60 ? packet[60] : 0,
                size > 61 ? packet[61] : 0,
                size > 62 ? packet[62] : 0,
                size > 63 ? packet[63] : 0);
        }
        offset += size;
        ++packet_count;
    }
}

void RevanaTraceWorldErrorState()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto*    ctx = rex::runtime::current_ppc_context();
    const uint32_t trace_index =
        g_world_error_trace_count.fetch_add(1, std::memory_order_relaxed);
    if (trace_index >= 96)
    {
        return;
    }
    const auto*    memory         = rex::runtime::ThreadState::Get()->memory();
    const uint32_t packet_address = ctx->r30.u32;
    if ((ctx->lr == 0x84197840 || ctx->lr == 0x841978D8) &&
        packet_address != 0)
    {
        const auto* packet =
            memory->TranslateVirtual<const uint8_t*>(packet_address);
        const uint16_t header = static_cast<uint16_t>(packet[0]) |
                                static_cast<uint16_t>(packet[1] << 8);
        const uint16_t id     = header & 0x1FF;
        const uint32_t size   = 2U * (packet[1] & 0xFE);
        REXLOG_WARN(
            "Xbox world packet error: code=0x{:02X} caller=0x{:08X} "
            "id=0x{:03X} size={} bytes={:02X} {:02X} {:02X} {:02X} "
            "{:02X} {:02X} {:02X} {:02X}",
            ctx->r3.u32,
            ctx->lr,
            id,
            size,
            packet[0],
            packet[1],
            packet[2],
            packet[3],
            packet[4],
            packet[5],
            packet[6],
            packet[7]);
        return;
    }
    REXLOG_WARN("Xbox world error state set: code=0x{:02X} caller=0x{:08X}",
                ctx->r3.u32,
                ctx->lr);
}

void RevanaTraceWorldDispatch()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const uint32_t trace_index =
        g_world_dispatch_trace_count.fetch_add(1, std::memory_order_relaxed);
    if (trace_index >= 1024)
    {
        return;
    }
    const auto*    ctx            = rex::runtime::current_ppc_context();
    const uint32_t packet_address = ctx->r5.u32;
    if (packet_address == 0)
    {
        return;
    }
    const auto* memory = rex::runtime::ThreadState::Get()->memory();
    const auto* packet =
        memory->TranslateVirtual<const uint8_t*>(packet_address);
    const uint16_t header = static_cast<uint16_t>(packet[0]) |
                            static_cast<uint16_t>(packet[1] << 8);
    REXLOG_INFO(
        "Xbox world dispatch: id=0x{:03X} size={} handler=0x{:08X} "
        "namespace=0x{:08X}",
        header & 0x1FF,
        2U * (packet[1] & 0xFE),
        ctx->ctr.u32,
        ctx->lr);
}

void RevanaTraceWorldFatalState()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const uint32_t trace_index =
        g_world_fatal_trace_count.fetch_add(1, std::memory_order_relaxed);
    if (trace_index >= 16)
    {
        return;
    }
    const auto*    ctx           = rex::runtime::current_ppc_context();
    const auto*    memory        = rex::runtime::ThreadState::Get()->memory();
    const uint32_t event_address = ctx->r5.u32;
    if (event_address == 0)
    {
        REXLOG_WARN("Xbox world fatal callback: caller=0x{:08X} event=null",
                    ctx->lr);
        return;
    }
    const auto*    event = memory->TranslateVirtual<const uint8_t*>(event_address);
    const uint32_t event_type =
        rex::memory::load_and_swap<uint32_t>(event + 4);
    REXLOG_WARN(
        "Xbox world fatal callback: caller=0x{:08X} event=0x{:08X} "
        "type=0x{:08X} bytes={:02X} {:02X} {:02X} {:02X} {:02X} {:02X} "
        "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} "
        "{:02X} {:02X}",
        ctx->lr,
        event_address,
        event_type,
        event[0],
        event[1],
        event[2],
        event[3],
        event[4],
        event[5],
        event[6],
        event[7],
        event[8],
        event[9],
        event[10],
        event[11],
        event[12],
        event[13],
        event[14],
        event[15]);
}

void RevanaTraceObjectBuildEntry()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const uint32_t trace_index =
        g_object_build_trace_count.fetch_add(1, std::memory_order_relaxed);
    if (trace_index >= 128)
    {
        return;
    }
    const auto* ctx    = rex::runtime::current_ppc_context();
    const auto* memory = rex::runtime::ThreadState::Get()->memory();
    if (ctx->r5.u32 == 0)
    {
        REXLOG_INFO(
            "Xbox object build: caller=0x{:08X} manager=0x{:08X} input=null "
            "aux=0x{:08X} resource=0x{:08X} requested_by=0x{:08X}",
            ctx->lr,
            ctx->r4.u32,
            ctx->r6.u32,
            g_resource_load_id,
            g_resource_load_caller);
        return;
    }
    const auto* input = memory->TranslateVirtual<const uint8_t*>(ctx->r5.u32);
    REXLOG_INFO(
        "Xbox object build: caller=0x{:08X} manager=0x{:08X} "
        "input=0x{:08X} aux=0x{:08X} resource=0x{:08X} "
        "requested_by=0x{:08X} bytes={:02X} {:02X} {:02X} {:02X} "
        "{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} "
        "{:02X} {:02X} {:02X} {:02X}",
        ctx->lr,
        ctx->r4.u32,
        ctx->r5.u32,
        ctx->r6.u32,
        g_resource_load_id,
        g_resource_load_caller,
        input[0],
        input[1],
        input[2],
        input[3],
        input[4],
        input[5],
        input[6],
        input[7],
        input[8],
        input[9],
        input[10],
        input[11],
        input[12],
        input[13],
        input[14],
        input[15]);
}

void RevanaTraceObjectBuildNull()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx = rex::runtime::current_ppc_context();
    REXLOG_ERROR(
        "Xbox object build null predecessor: caller=0x{:08X} manager=0x{:08X} "
        "input=0x{:08X} current=0x{:08X} node=0x{:08X} cache=0x{:08X}",
        ctx->lr,
        ctx->r15.u32,
        ctx->r31.u32,
        ctx->r14.u32,
        ctx->r27.u32,
        ctx->r9.u32);
}

void RevanaTraceResourceLoadEntry()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx        = rex::runtime::current_ppc_context();
    g_resource_load_id     = ctx->r5.u32;
    g_resource_load_caller = ctx->lr;
}

void RevanaTraceWorldPacketDequeued()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx = rex::runtime::current_ppc_context();
    if (g_world_packet_dequeue_result.exchange(ctx->r3.u32,
                                               std::memory_order_relaxed) ==
        ctx->r3.u32)
    {
        return;
    }
    REXLOG_INFO("Xbox world packet dequeue result=0x{:08X}", ctx->r3.u32);
}

void RevanaTraceWorldSendEntry()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx = rex::runtime::current_ppc_context();
    REXLOG_INFO("Xbox world packet send entered: owner=0x{:08X} caller=0x{:08X}",
                ctx->r3.u32,
                ctx->lr);
}

void RevanaTraceWorldSendTarget()
{
    const auto* ctx    = rex::runtime::current_ppc_context();
    const auto* memory = rex::runtime::ThreadState::Get()->memory();
    if (ctx->r4.u32 == 0 || ctx->r7.u32 == 0 || ctx->r27.u32 < 8)
    {
        if (g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
        {
            REXLOG_WARN(
                "Xbox world send arguments invalid: packet=0x{:08X} "
                "target=0x{:08X} target_length={}",
                ctx->r4.u32,
                ctx->r7.u32,
                ctx->r27.u32);
        }
        return;
    }
    auto* packet = memory->TranslateVirtual<uint8_t*>(ctx->r4.u32);
    if (kRestoreWorldLoginCharacterId)
    {
        RestoreWorldLoginCharacterId(packet, ctx->r5.u32);
    }
    auto*          target = memory->TranslateVirtual<uint8_t*>(ctx->r7.u32);
    const uint16_t original_port =
        static_cast<uint16_t>((target[2] << 8) | target[3]);
    if ((original_port == 0 || original_port == UINT16_MAX) &&
        g_direct_map_endpoint_enabled.load(std::memory_order_acquire))
    {
        const uint16_t port =
            g_direct_map_port.load(std::memory_order_relaxed);
        const uint32_t ipv4 =
            g_direct_map_ipv4.load(std::memory_order_relaxed);
        target[0] = 0;
        target[1] = 2;
        target[2] = static_cast<uint8_t>(port >> 8);
        target[3] = static_cast<uint8_t>(port);
        target[4] = static_cast<uint8_t>(ipv4 >> 24);
        target[5] = static_cast<uint8_t>(ipv4 >> 16);
        target[6] = static_cast<uint8_t>(ipv4 >> 8);
        target[7] = static_cast<uint8_t>(ipv4);
        REXLOG_WARN(
            "Xbox direct mode restored missing world endpoint to {}.{}.{}.{}:{}",
            target[4],
            target[5],
            target[6],
            target[7],
            port);
    }
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    constexpr size_t kOuterHeaderSize = 28;
    constexpr size_t kLoginPacketSize = 92;
    constexpr size_t kOuterDigestSize = 16;
    if (ctx->r5.u32 >=
            kOuterHeaderSize + kLoginPacketSize + kOuterDigestSize &&
        (ReadLe32(packet + kOuterHeaderSize) & 0x1FF) == 0x0A)
    {
        const size_t plaintext_size =
            ctx->r5.u32 - kOuterHeaderSize - kOuterDigestSize;
        const uint32_t trailing_packet_id =
            plaintext_size > kLoginPacketSize
                ? ReadLe32(packet + kOuterHeaderSize + kLoginPacketSize) & 0x1FF
                : UINT32_MAX;
        REXLOG_INFO(
            "Xbox world login fields: check=0x{:02X} state=0x{:04X} "
            "error=0x{:08X} character=0x{:08X} area=0x{:04X} "
            "plaintext_size={} trailing_packet={}",
            packet[kOuterHeaderSize + 4],
            ReadLe16(packet + kOuterHeaderSize + 6),
            ReadLe32(packet + kOuterHeaderSize + 8),
            ReadLe32(packet + kOuterHeaderSize + 12),
            ReadLe16(packet + kOuterHeaderSize + 90),
            plaintext_size,
            trailing_packet_id == UINT32_MAX
                ? "none"
                : fmt::format("0x{:03X}", trailing_packet_id));
    }
    const uint16_t family =
        static_cast<uint16_t>((target[0] << 8) | target[1]);
    const uint16_t port        = static_cast<uint16_t>((target[2] << 8) | target[3]);
    const uint32_t ipv4        = (static_cast<uint32_t>(target[4]) << 24) |
                                 (static_cast<uint32_t>(target[5]) << 16) |
                                 (static_cast<uint32_t>(target[6]) << 8) | target[7];
    const uint64_t observation = (static_cast<uint64_t>(family) << 48) |
                                 (static_cast<uint64_t>(port) << 32) | ipv4;
    if (g_world_send_target.exchange(observation, std::memory_order_relaxed) ==
        observation)
    {
        return;
    }
    if (ctx->r5.u32 < 48)
    {
        REXLOG_INFO(
            "Xbox world send target: family={} ipv4={}.{}.{}.{} port={} "
            "target_length={} packet_length={}",
            family,
            (ipv4 >> 24) & 0xFF,
            (ipv4 >> 16) & 0xFF,
            (ipv4 >> 8) & 0xFF,
            ipv4 & 0xFF,
            port,
            ctx->r27.u32,
            ctx->r5.u32);
        return;
    }
    REXLOG_INFO(
        "Xbox world send target: family={} ipv4={}.{}.{}.{} port={} "
        "target_length={} packet_length={} header="
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}"
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X} body="
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}"
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}"
        "{:02X}{:02X}{:02X}{:02X}",
        family,
        (ipv4 >> 24) & 0xFF,
        (ipv4 >> 16) & 0xFF,
        (ipv4 >> 8) & 0xFF,
        ipv4 & 0xFF,
        port,
        ctx->r27.u32,
        ctx->r5.u32,
        packet[0],
        packet[1],
        packet[2],
        packet[3],
        packet[4],
        packet[5],
        packet[6],
        packet[7],
        packet[8],
        packet[9],
        packet[10],
        packet[11],
        packet[12],
        packet[13],
        packet[14],
        packet[15],
        packet[28],
        packet[29],
        packet[30],
        packet[31],
        packet[32],
        packet[33],
        packet[34],
        packet[35],
        packet[36],
        packet[37],
        packet[38],
        packet[39],
        packet[40],
        packet[41],
        packet[42],
        packet[43],
        packet[44],
        packet[45],
        packet[46],
        packet[47]);
}

void RevanaTraceWorldSendResult()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx = rex::runtime::current_ppc_context();
    REXLOG_INFO("Xbox world sendto returned {}", ctx->r3.s32);
}

void RevanaTraceWorldStatusSet()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto*    ctx   = rex::runtime::current_ppc_context();
    const uint32_t flags = ctx->r3.u32;
    if ((flags & 0x44) == 0 ||
        g_world_status_set_count.fetch_add(1, std::memory_order_relaxed) >= 32)
    {
        return;
    }
    REXLOG_INFO("Xbox world status set: flags=0x{:08X} caller=0x{:08X}", flags, ctx->lr);
}

void RevanaTraceLobbyControllerFailure()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox lobby controller initialization returned failure");
    }
}

void RevanaTracePolError2071MapperA()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        REXLOG_INFO(
            "Xbox POL error mapper sub_82462A48 selected -2071 from raw={} "
            "caller=0x{:08X}",
            ctx->r3.s32,
            ctx->lr);
    }
}

void RevanaTracePolError2071MapperB()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        REXLOG_INFO(
            "Xbox POL error mapper sub_82465678 selected -2071 from raw={} "
            "caller=0x{:08X}",
            ctx->r3.s32,
            ctx->lr);
    }
}

void RevanaTracePolServiceOpenEntry()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        REXLOG_INFO(
            "Xbox PolCore sub_82465C88 entry caller=0x{:08X} argument=0x{:08X}",
            ctx->lr,
            ctx->r3.u32);
    }
}

void RevanaTracePolError2071UninitializedA()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        REXLOG_INFO(
            "Xbox PolCore sub_82465C88 returned -2071 for uninitialized service "
            "caller=0x{:08X}",
            ctx->lr);
    }
}

void RevanaTracePolError2071UninitializedB()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        REXLOG_INFO(
            "Xbox PolCore sub_82465D90 returned -2071 for uninitialized service "
            "caller=0x{:08X}",
            ctx->lr);
    }
}

void RevanaTracePolError2071UninitializedC()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        REXLOG_INFO(
            "Xbox PolCore sub_82465ED8 returned -2071 for uninitialized service "
            "caller=0x{:08X}",
            ctx->lr);
    }
}

bool RevanaConfigureDirectLobbyViewBootstrap(uint16_t       view_port,
                                             const uint8_t* packet,
                                             size_t         packet_size)
{
    if (view_port == 0 || !packet ||
        packet_size != g_direct_view_bootstrap_packet.size())
    {
        REXLOG_ERROR("Xbox direct view bootstrap configuration is invalid");
        return false;
    }
    std::memcpy(g_direct_view_bootstrap_packet.data(), packet, packet_size);
    g_direct_view_bootstrap_port = view_port;
    g_direct_view_bootstrap_sent.store(false, std::memory_order_relaxed);
    g_direct_view_bootstrap_enabled.store(true, std::memory_order_release);
    REXLOG_INFO("Xbox direct view bootstrap armed for port {}", view_port);
    return true;
}

bool RevanaConfigureDirectMapCipherKey(const uint8_t* key,
                                       size_t         key_size)
{
    if (!key || key_size != g_direct_map_cipher_key.size())
    {
        REXLOG_ERROR("Xbox direct map cipher key configuration is invalid");
        return false;
    }
    std::copy_n(key, key_size, g_direct_map_cipher_key.begin());
    g_direct_map_cipher_key_reported.store(false, std::memory_order_relaxed);
    g_direct_map_cipher_key_enabled.store(true, std::memory_order_release);
    return true;
}

void RevanaClearDirectMapCipherKey()
{
    g_direct_map_cipher_key_enabled.store(false, std::memory_order_release);
#if defined(_WIN32)
    SecureZeroMemory(g_direct_map_cipher_key.data(),
                     g_direct_map_cipher_key.size());
#else
    g_direct_map_cipher_key.fill(0);
#endif
    g_direct_map_cipher_key_reported.store(false, std::memory_order_relaxed);
}

bool RevanaConfigureDirectMapEndpoint(uint32_t ipv4_address,
                                      uint16_t port)
{
    if (ipv4_address == 0 || port == 0 || port == UINT16_MAX)
    {
        REXLOG_ERROR("Xbox direct map endpoint configuration is invalid");
        return false;
    }
    g_direct_map_ipv4.store(ipv4_address, std::memory_order_relaxed);
    g_direct_map_port.store(port, std::memory_order_relaxed);
    g_direct_map_endpoint_enabled.store(true, std::memory_order_release);
    return true;
}

void RevanaClearDirectMapEndpoint()
{
    g_direct_map_endpoint_enabled.store(false, std::memory_order_release);
    g_direct_map_ipv4.store(0, std::memory_order_relaxed);
    g_direct_map_port.store(0, std::memory_order_relaxed);
}

void RevanaTraceConfigHandshakeState()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto*    ctx      = rex::runtime::current_ppc_context();
    const auto*    memory   = rex::runtime::ThreadState::Get()->memory();
    const uint32_t object   = ctx->r3.u32;
    const uint32_t state    = *memory->TranslateVirtual<const uint8_t*>(object + 9);
    const uint64_t observed = (static_cast<uint64_t>(object) << 32) | state;
    if (g_config_handshake_state.exchange(observed, std::memory_order_relaxed) ==
            observed ||
        !GuestTraceHooksEnabled())
    {
        return;
    }
    REXLOG_INFO(
        "Xbox config handshake state={} object=0x{:08X} caller=0x{:08X}",
        state,
        object,
        ctx->lr);
}

void RevanaTraceConfigHandshakeReturn()
{
    if (!GuestTraceHooksEnabled())
    {
        return;
    }
    const auto* ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    const uint32_t object = ctx->r31.u32;
    REXLOG_INFO(
        "Xbox config handshake return={} state={} object=0x{:08X} "
        "session=0x{:08X} sent={} received={}",
        ctx->r3.s32,
        *memory->TranslateVirtual<const uint8_t*>(object + 9),
        object,
        load_word(object + 4),
        load_word(object + 68),
        load_word(object + 72));
}

void RevanaTraceConfigRequest()
{
    if (!GuestTraceHooksEnabled())
    {
        return;
    }
    const auto* ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    const uint32_t object = ctx->r31.u32;
    if (load_word(object + 68) != 0)
    {
        return;
    }
    const uint32_t buffer = load_word(object + 64);
    REXLOG_INFO(
        "Xbox config request object=0x{:08X} buffer=0x{:08X} "
        "bytes={:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
        object,
        buffer,
        load_word(buffer),
        load_word(buffer + 4),
        load_word(buffer + 8),
        load_word(buffer + 12),
        load_word(buffer + 16),
        load_word(buffer + 20),
        load_word(buffer + 24),
        load_word(buffer + 28),
        load_word(buffer + 32),
        load_word(buffer + 36));
}

void RevanaTraceConfigResponse()
{
    if (!GuestTraceHooksEnabled())
    {
        return;
    }
    const auto* ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    const uint32_t object = ctx->r31.u32;
    const uint32_t buffer = load_word(object + 60);
    REXLOG_INFO(
        "Xbox config response object=0x{:08X} buffer=0x{:08X} "
        "bytes={:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
        object,
        buffer,
        load_word(buffer),
        load_word(buffer + 4),
        load_word(buffer + 8),
        load_word(buffer + 12),
        load_word(buffer + 16),
        load_word(buffer + 20));
}

void RevanaTraceConfigServiceState()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto*    ctx      = rex::runtime::current_ppc_context();
    const auto*    memory   = rex::runtime::ThreadState::Get()->memory();
    const uint32_t object   = ctx->r31.u32;
    const uint32_t state    = *memory->TranslateVirtual<const uint8_t*>(object + 8);
    const uint64_t observed = (static_cast<uint64_t>(object) << 32) | state;
    if (g_config_service_state.exchange(observed, std::memory_order_relaxed) ==
            observed ||
        !GuestTraceHooksEnabled())
    {
        return;
    }
    REXLOG_INFO("Xbox config service state={} object=0x{:08X}", state, object);
}

void RevanaTraceConfigParserState()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    const uint32_t object   = ctx->r31.u32;
    const uint32_t state    = *memory->TranslateVirtual<const uint8_t*>(object + 10);
    const uint64_t observed = (static_cast<uint64_t>(object) << 32) | state;
    if (g_config_parser_state.exchange(observed, std::memory_order_relaxed) ==
            observed ||
        !GuestTraceHooksEnabled())
    {
        return;
    }
    REXLOG_INFO(
        "Xbox config parser state={} object=0x{:08X} active={} "
        "record=0x{:08X}/{} command={}/{}",
        state,
        object,
        *memory->TranslateVirtual<const uint8_t*>(object + 212),
        load_word(object + 200),
        load_word(object + 204),
        *memory->TranslateVirtual<const uint8_t*>(object + 609),
        *memory->TranslateVirtual<const uint8_t*>(object + 610));
}

void RevanaTraceConfigFollowupState()
{
    if (!GuestTraceHooksEnabled())
    {
        return;
    }
    const auto* ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    const uint32_t object = ctx->r31.u32;
    REXLOG_INFO(
        "Xbox config followup object=0x{:08X} data=0x{:08X} "
        "session_cipher_table=0x{:08X} response_word=0x{:08X} "
        "network_word=0x{:08X} encrypted={}",
        object,
        load_word(object + 808),
        load_word(object + 152),
        load_word(object + 184),
        load_word(object + 812),
        *memory->TranslateVirtual<const uint8_t*>(object + 11));
}

void RevanaTraceConfigTransferState()
{
    if (!GuestTraceHooksEnabled())
    {
        return;
    }
    const auto* ctx       = rex::runtime::current_ppc_context();
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    const uint32_t object = ctx->r31.u32;
    const uint8_t  state =
        *memory->TranslateVirtual<const uint8_t*>(object + 8);
    const uint8_t transport_state =
        *memory->TranslateVirtual<const uint8_t*>(object + 9);
    const uint32_t progress = load_word(object + 28);
    const uint64_t observed = (static_cast<uint64_t>(object) << 32) |
                              (static_cast<uint64_t>(state) << 24) |
                              (static_cast<uint64_t>(transport_state) << 16) |
                              (progress & 0xFFFF);
    if (g_config_transfer_state.exchange(observed, std::memory_order_relaxed) ==
        observed)
    {
        return;
    }
    REXLOG_INFO(
        "Xbox config transfer state={} transport={} result={} total={} "
        "progress={} chunk_bytes={} mode={} send_progress={} io_progress={}",
        state,
        transport_state,
        ctx->r30.s32,
        load_word(object + 196),
        progress,
        load_word(object + 200),
        load_word(object + 204),
        load_word(object + 68),
        load_word(object + 72));
}

void RevanaTraceFourByteSocketReceive()
{
    const auto* ctx = rex::runtime::current_ppc_context();
    if (ctx->r5.u32 != 4)
    {
        return;
    }
    auto*          kernel_state = rex::runtime::current_kernel_state();
    const uint32_t descriptor   = ctx->r3.u32;
    const uint32_t object_handle =
        descriptor >= rex::system::XObject::kHandleBase
            ? descriptor
            : descriptor + rex::system::XObject::kHandleBase;
    auto socket = kernel_state
                      ? kernel_state->object_table()
                            ->LookupObject<rex::system::XSocket>(object_handle)
                      : nullptr;
    if (g_direct_view_bootstrap_enabled.load(std::memory_order_acquire) &&
        !g_direct_view_bootstrap_sent.load(std::memory_order_relaxed))
    {
        if (socket && socket->peer_port() == g_direct_view_bootstrap_port)
        {
            const int sent = socket->Send(g_direct_view_bootstrap_packet.data(),
                                          g_direct_view_bootstrap_packet.size(),
                                          0);
            if (sent == static_cast<int>(g_direct_view_bootstrap_packet.size()))
            {
                g_direct_view_bootstrap_sent.store(true, std::memory_order_relaxed);
                std::fill(g_direct_view_bootstrap_packet.begin(),
                          g_direct_view_bootstrap_packet.end(),
                          0);
                bool    response_ready = false;
                uint8_t probe          = 0;
                for (uint32_t attempt = 0; attempt < 100; ++attempt)
                {
                    if (socket->Recv(&probe, 1, kSocketMessagePeek) > 0)
                    {
                        response_ready = true;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
                REXLOG_INFO(
                    "Xbox direct view bootstrap sent authenticated request: "
                    "size={} port={} response_ready={}",
                    sent,
                    socket->peer_port(),
                    response_ready);
            }
            else
            {
                REXLOG_ERROR(
                    "Xbox direct view bootstrap send failed: sent={} expected={}",
                    sent,
                    g_direct_view_bootstrap_packet.size());
            }
        }
    }
    const bool trace_enabled        = GuestTraceHooksEnabled();
    const bool restore_character_id = kRestoreWorldLoginCharacterId;
    if ((trace_enabled || restore_character_id) && socket &&
        socket->peer_port() == g_direct_view_bootstrap_port)
    {
        std::array<uint8_t, 12> header{};
        const int               peeked = socket->Recv(header.data(), header.size(), kSocketMessagePeek);
        if (peeked == static_cast<int>(header.size()))
        {
            const uint32_t packet_size = ReadLe32(header.data());
            const uint32_t command     = ReadLe32(header.data() + 8);
            if (trace_enabled)
            {
                REXLOG_INFO("Xbox lobby receive header: size={} command={:02X}",
                            packet_size,
                            command);
            }
            if (packet_size == 72 && command == 0x0B)
            {
                std::array<uint8_t, 72> response{};
                const int               response_peeked = socket->Recv(
                    response.data(), response.size(), kSocketMessagePeek);
                if (response_peeked == static_cast<int>(response.size()))
                {
                    g_lobby_next_login_character_id.store(
                        ReadLe32(response.data() + 28), std::memory_order_release);
                    if (trace_enabled)
                    {
                        REXLOG_INFO(
                            "Xbox lobby next-login: ffxi_id=0x{:08X} "
                            "ffxi_id_world=0x{:08X} server_id=0x{:08X} "
                            "server_ipv4=0x{:08X} server_port={} "
                            "cache_ipv4=0x{:08X} cache_port={}",
                            ReadLe32(response.data() + 28),
                            ReadLe32(response.data() + 32),
                            ReadLe32(response.data() + 52),
                            ReadLe32(response.data() + 56),
                            ReadLe32(response.data() + 60),
                            ReadLe32(response.data() + 64),
                            ReadLe32(response.data() + 68));
                    }
                }
            }
        }
    }
    if (!trace_enabled)
    {
        return;
    }
    const auto* memory    = rex::runtime::ThreadState::Get()->memory();
    const auto  load_word = [memory](uint32_t address)
    {
        return rex::memory::load_and_swap<uint32_t>(
            memory->TranslateVirtual<const uint32_t*>(address));
    };
    REXLOG_INFO(
        "Xbox four-byte socket receive caller=0x{:08X} socket={} "
        "buffer=0x{:08X} prior=0x{:08X} current=0x{:08X}",
        static_cast<uint32_t>(ctx->lr),
        ctx->r3.u32,
        ctx->r4.u32,
        load_word(ctx->r4.u32 - 4),
        load_word(ctx->r4.u32));
}

void RevanaTraceGuestExceptionRaise()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx = rex::runtime::current_ppc_context();
    REXLOG_ERROR(
        "Xbox guest exception raise caller=0x{:08X} code=0x{:08X} "
        "flags={} parameters={} information=0x{:08X}",
        static_cast<uint32_t>(ctx->lr),
        ctx->r3.u32,
        ctx->r4.u32,
        ctx->r5.u32,
        ctx->r6.u32);
}

void RevanaTraceGuestCppThrow()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx = rex::runtime::current_ppc_context();
    REXLOG_ERROR(
        "Xbox guest C++ throw caller=0x{:08X} object=0x{:08X} "
        "throw_info=0x{:08X}",
        static_cast<uint32_t>(ctx->lr),
        ctx->r3.u32,
        ctx->r4.u32);
}

void RevanaTraceFrameStateTransition()
{
    if (!g_guest_trace_hooks_enabled.load(std::memory_order_relaxed))
    {
        return;
    }
    const auto* ctx = rex::runtime::current_ppc_context();
    if (ctx->r11.u32 == ctx->r10.u32)
    {
        return;
    }
    REXLOG_INFO("Xbox frame state transition {} -> {} object=0x{:08X}",
                ctx->r10.u32,
                ctx->r11.u32,
                ctx->r30.u32);
}

void RevanaTraceMainBootstrapEntry()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main bootstrap entered");
    }
}

void RevanaTraceMainBootstrapConfigReady()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main bootstrap configuration ready");
    }
}

void RevanaTraceMainBootstrapServicesReady()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main bootstrap services ready");
    }
}

void RevanaTraceMainBootstrapGraphicsReady()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main bootstrap graphics ready");
    }
}

void RevanaTraceMainDispatchEntry()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main dispatch entered");
    }
}

void RevanaTraceMainDispatchObjectReady()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main dispatch object ready");
    }
}

void RevanaTraceMainLoopEntry()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main loop entered");
    }
}

void RevanaTraceFfxiExportEntry()
{
    if (GuestTraceHooksEnabled())
    {
        const auto* ctx = rex::runtime::current_ppc_context();
        if (ctx->r3.u32 == 0)
        {
            REXLOG_INFO("Xbox FFXi module entry invoked without a service table");
            return;
        }
        const auto* memory    = rex::runtime::ThreadState::Get()->memory();
        const auto  load_word = [memory](uint32_t address)
        {
            return address == 0
                       ? 0
                       : rex::memory::load_and_swap<uint32_t>(
                             memory->TranslateVirtual<const uint32_t*>(address));
        };
        const uint32_t services = ctx->r3.u32;
        REXLOG_INFO(
            "Xbox FFXi export service table=0x{:08X} targets "
            "+1684=0x{:08X} +3876=0x{:08X} +4104=0x{:08X}",
            services,
            load_word(services + 1684),
            load_word(services + 3876),
            load_word(services + 4104));
    }
}

void RevanaSelectPolCoreEnglish()
{
    auto*          ctx           = rex::runtime::current_ppc_context();
    const uint32_t observed_mode = ctx->r3.u32;
    ctx->r3.u32                  = 1;
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox PolCore mode service selected English ({} -> 1)",
                    observed_mode);
    }
}

void RevanaTraceFfxiMainOrdinal2Call()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox FFXi requested FFXiMain ordinal 2 call");
    }
}

void RevanaTraceFfxiMainOrdinal3Call()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox FFXi requested FFXiMain ordinal 3 call");
    }
}

void RevanaTraceFfxiMainOrdinal4Call()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox FFXi requested FFXiMain ordinal 4 call");
    }
}

void RevanaTraceFfxiMainOrdinal5Call()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox FFXi requested FFXiMain ordinal 5 call");
    }
}

void RevanaTraceMainLoopSystemReady()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main loop system precondition ready");
    }
}

void RevanaTraceMainLoopHostReady()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main loop host precondition ready");
    }
}

void RevanaTraceMainLoopFrameAllocated()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main loop frame object allocated");
    }
}

void RevanaTraceMainLoopWorkerStarted()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main loop startup worker started");
    }
}

void RevanaTraceMainLoopWorkerReady()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main loop startup worker reported ready");
    }
}

void RevanaTraceMainLoopCleanup()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main loop entered cleanup");
    }
}

void RevanaTraceMainLoopDeviceProbe()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox main loop entered device probe");
    }
}

void RevanaTraceStartupSelector13LoadReturned()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox startup selector 13 load returned");
    }
}

void RevanaTraceStartupWorkerFailure()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox startup worker returned failure");
    }
}

void RevanaTracePackageMetadataFailure()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox package metadata check returned failure");
    }
}

void RevanaTraceStartupPackageValidationFailure()
{
    if (GuestTraceHooksEnabled())
    {
        REXLOG_INFO("Xbox startup package validation returned failure");
    }
}
