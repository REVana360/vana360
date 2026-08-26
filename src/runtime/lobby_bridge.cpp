#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>

#include <windows.h>

#include <ws2tcpip.h>

#include "lobby_bridge.h"

#include "revana_hooks.h"

#include <login/auth_client.h>
#include <login/lobby_client.h>
#include <login/lobby_packets.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <rex/cvar.h>
#include <rex/logging.h>
#include <rex/memory.h>
#include <rex/system/function_dispatcher.h>
#include <rex/system/xsocket.h>

namespace
{

using revana::login::AuthCredentials;
using revana::login::AuthOptions;
using revana::login::CertificateSha256;
using revana::login::ClientVersion;
using revana::login::LobbyOptions;

std::optional<std::string> ReadEnvironment(const char* name)
{
    char*  value = nullptr;
    size_t size  = 0;
    if (_dupenv_s(&value, &size, name) != 0 || !value || size <= 1)
    {
        std::free(value);
        return std::nullopt;
    }
    std::string result(value, size - 1);
    SecureZeroMemory(value, size);
    std::free(value);
    return result;
}

std::optional<uint16_t> ParsePort(const std::optional<std::string>& value,
                                  uint16_t                          fallback)
{
    if (!value)
    {
        return fallback;
    }
    uint32_t   parsed = 0;
    const auto result =
        std::from_chars(value->data(), value->data() + value->size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value->data() + value->size() ||
        parsed == 0 || parsed > UINT16_MAX)
    {
        return std::nullopt;
    }
    return static_cast<uint16_t>(parsed);
}

std::optional<CertificateSha256>
ParseCertificatePin(const std::optional<std::string>& value)
{
    if (!value)
    {
        return CertificateSha256{};
    }
    if (value->size() != revana::login::kCertificateSha256Size * 2)
    {
        return std::nullopt;
    }

    CertificateSha256 result{};
    for (size_t i = 0; i < result.size(); ++i)
    {
        uint32_t    byte   = 0;
        const char* first  = value->data() + i * 2;
        const auto  parsed = std::from_chars(first, first + 2, byte, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != first + 2)
        {
            return std::nullopt;
        }
        result[i] = static_cast<uint8_t>(byte);
    }
    return result;
}

void ClearString(std::string& value)
{
    if (!value.empty())
    {
        SecureZeroMemory(value.data(), value.size());
        value.clear();
    }
}

uint32_t ReadLe32(std::span<const uint8_t> bytes, size_t offset)
{
    return static_cast<uint32_t>(bytes[offset]) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

uint32_t ReadGuest32(rex::memory::Memory* memory, uint32_t address)
{
    return rex::memory::load_and_swap<uint32_t>(
        memory->TranslateVirtual(address));
}

uint8_t ReadGuest8(rex::memory::Memory* memory, uint32_t address)
{
    return *memory->TranslateVirtual(address);
}

struct LobbyControlState
{
    uint8_t  initialization_started;
    uint8_t  initialization_count;
    uint32_t update_stage;
    uint32_t flow_state;
    uint32_t flow_condition;
    uint32_t current_state;
    uint32_t prior_state;
    uint32_t readiness_state;
    uint32_t active;

    auto Tie() const
    {
        return std::tie(initialization_started, initialization_count, update_stage, flow_state, flow_condition, current_state, prior_state, readiness_state, active);
    }

    bool operator==(const LobbyControlState& other) const
    {
        return Tie() == other.Tie();
    }
};

std::optional<LobbyControlState> ReadLobbyControlState(
    rex::memory::Memory* memory, uint32_t object)
{
    if (object == 0 || object > UINT32_MAX - 156)
    {
        return std::nullopt;
    }
    LobbyControlState result{
        .initialization_started = ReadGuest8(memory, object),
        .initialization_count   = ReadGuest8(memory, object + 2),
        .update_stage           = ReadGuest32(memory, object + 8),
        .flow_state             = ReadGuest32(memory, object + 12),
        .flow_condition         = ReadGuest32(memory, object + 20),
        .current_state          = ReadGuest32(memory, object + 136),
        .prior_state            = ReadGuest32(memory, object + 140),
        .readiness_state        = ReadGuest32(memory, object + 144),
        .active                 = ReadGuest32(memory, object + 152),
    };
    return result;
}

} // namespace

struct RevanaLobbyBridge::State
{
    ~State()
    {
        SecureZeroMemory(session.session_hash.data(), session.session_hash.size());
        SecureZeroMemory(map_session_key.data(), map_session_key.size());
        session.account_id = 0;
        RevanaClearDirectMapCipherKey();
        RevanaClearDirectMapEndpoint();
    }

    std::string                  host;
    revana::login::AuthSession   session;
    revana::login::MapSessionKey map_session_key{};
    uint32_t                     ipv4      = 0;
    uint16_t                     data_port = revana::login::kLoginDataPort;
    uint16_t                     view_port = revana::login::kLoginViewPort;
    ClientVersion                client_version{};
    std::atomic_bool             data_coordination_started    = false;
    std::atomic_bool             bootstrap_view_login_pending = false;
};

bool RevanaLobbyBridge::Configure(rex::RuntimeConfig& config)
{
    auto host     = ReadEnvironment("REVANA_LOBBY_HOST");
    auto username = ReadEnvironment("REVANA_LOBBY_USERNAME");
    auto password = ReadEnvironment("REVANA_LOBBY_PASSWORD");
    auto otp      = ReadEnvironment("REVANA_LOBBY_OTP").value_or("");
    if (!host && !username && !password)
    {
        return false;
    }

    state_trace_enabled_ =
        ReadEnvironment("REVANA_LOBBY_STATE_TRACE").value_or("") == "1";
    if (!host || !username || !password)
    {
        REXLOG_ERROR("Lobby bridge configuration is incomplete");
        return false;
    }

    const auto auth_port       = ParsePort(ReadEnvironment("REVANA_LOBBY_AUTH_PORT"),
                                           revana::login::kLoginAuthPort);
    const auto data_port       = ParsePort(ReadEnvironment("REVANA_LOBBY_DATA_PORT"),
                                           revana::login::kLoginDataPort);
    const auto view_port       = ParsePort(ReadEnvironment("REVANA_LOBBY_VIEW_PORT"),
                                           revana::login::kLoginViewPort);
    const auto certificate_pin = ParseCertificatePin(
        ReadEnvironment("REVANA_LOBBY_CERTIFICATE_SHA256"));
    const auto client_version = ReadEnvironment("REVANA_LOBBY_CLIENT_VERSION");
    if (!auth_port || !data_port || !view_port || !certificate_pin ||
        !client_version || client_version->size() != ClientVersion{}.size() ||
        !std::all_of(client_version->begin(), client_version->end(), [](unsigned char byte)
                     {
                         return byte >= 0x20 && byte <= 0x7E;
                     }))
    {
        REXLOG_ERROR(
            "Lobby bridge port, certificate pin, or client version is invalid");
        return false;
    }

    in_addr address{};
    if (InetPtonA(AF_INET, host->c_str(), &address) != 1)
    {
        REXLOG_ERROR("Lobby bridge host must be an IPv4 address");
        return false;
    }

    AuthCredentials credentials{
        .username = std::move(*username),
        .password = std::move(*password),
        .otp      = std::move(otp),
    };
    AuthOptions auth_options{
        .port = *auth_port,
    };
    if (std::any_of(certificate_pin->begin(), certificate_pin->end(), [](uint8_t byte)
                    {
                        return byte != 0;
                    }))
    {
        auth_options.certificate_sha256 = *certificate_pin;
    }

    auto authenticated =
        revana::login::Authenticate(*host, credentials, auth_options);
    ClearString(credentials.username);
    ClearString(credentials.password);
    ClearString(credentials.otp);
    if (!authenticated)
    {
        REXLOG_ERROR("Lobby authentication failed: error={}",
                     static_cast<uint32_t>(authenticated.error().error));
        return false;
    }

    state_          = std::make_shared<State>();
    state_->host    = std::move(*host);
    state_->session = std::move(*authenticated);
    if (!revana::login::GenerateMapSessionKey(state_->map_session_key))
    {
        REXLOG_ERROR("Lobby map-session key generation failed");
        state_.reset();
        return false;
    }
    revana::login::MapCipherKey map_cipher_key{};
    if (!revana::login::DeriveMapCipherKey(state_->map_session_key,
                                           map_cipher_key) ||
        !RevanaConfigureDirectMapCipherKey(map_cipher_key.data(),
                                           map_cipher_key.size()))
    {
        SecureZeroMemory(map_cipher_key.data(), map_cipher_key.size());
        REXLOG_ERROR("Lobby map-cipher key derivation failed");
        state_.reset();
        return false;
    }
    SecureZeroMemory(map_cipher_key.data(), map_cipher_key.size());
    state_->ipv4      = ntohl(address.s_addr);
    state_->data_port = *data_port;
    state_->view_port = *view_port;
    if (!RevanaConfigureDirectMapEndpoint(state_->ipv4,
                                          state_->data_port))
    {
        state_.reset();
        return false;
    }

    std::copy(client_version->begin(), client_version->end(), state_->client_version.begin());
    auto view_login = revana::login::MakeViewLogin(
        state_->session.session_hash, state_->client_version);
    if (!RevanaConfigureDirectLobbyViewBootstrap(
            state_->view_port, view_login.data(), view_login.size()))
    {
        SecureZeroMemory(view_login.data(), view_login.size());
        return false;
    }
    SecureZeroMemory(view_login.data(), view_login.size());
    state_->bootstrap_view_login_pending.store(true,
                                               std::memory_order_release);

    const auto state = state_;
    config.network_hooks.resolve_ipv4 =
        [state](uint32_t /*caller*/, std::string_view hostname)
        -> std::optional<uint32_t>
    {
        constexpr std::string_view prefix = "ffxi";
        constexpr std::string_view suffix = ".pol.com";
        const bool                 numbered_ffxi_host =
            hostname.size() == prefix.size() + 2 + suffix.size() &&
            hostname.starts_with(prefix) &&
            hostname.substr(prefix.size() + 2) == suffix &&
            hostname[prefix.size()] >= '0' && hostname[prefix.size()] <= '9' &&
            hostname[prefix.size() + 1] >= '0' &&
            hostname[prefix.size() + 1] <= '9';
        if (!numbered_ffxi_host && hostname != "pp000.pol.com")
        {
            return std::nullopt;
        }
        return state->ipv4;
    };
    config.network_hooks.before_connect =
        [this, state](uint32_t caller, rex::system::N_XSOCKADDR& address, int address_length)
    {
        if (address.address_family != rex::system::XSocket::X_AF_INET ||
            address_length < sizeof(rex::system::N_XSOCKADDR_IN))
        {
            return;
        }
        auto& ipv4_address =
            reinterpret_cast<rex::system::N_XSOCKADDR_IN&>(address);
        if (ipv4_address.sin_port != state->view_port)
        {
            return;
        }
        ipv4_address.sin_addr = state->ipv4;
        if (!state->data_coordination_started.exchange(true))
        {
            data_thread_ = std::jthread([state](std::stop_token stop_token)
                                        {
                                            const auto result =
                                                revana::login::CoordinateCharacterLoginData(
                                                    state->host, state->session, state->map_session_key, stop_token, LobbyOptions{
                                                                                                                         .data_port = state->data_port,
                                                                                                                         .view_port = state->view_port,
                                                                                                                     });
                                            if (!result)
                                            {
                                                if (result.error().error ==
                                                    revana::login::LobbyError::kCancelled)
                                                {
                                                    REXLOG_INFO("Lobby data coordination cancelled");
                                                }
                                                else
                                                {
                                                    REXLOG_ERROR(
                                                        "Lobby data coordination failed: error={} stage={}",
                                                        static_cast<uint32_t>(result.error().error),
                                                        static_cast<uint32_t>(result.error().stage));
                                                }
                                            }
                                            else
                                            {
                                                REXLOG_INFO(
                                                    "Lobby character selection coordinated: slot_count={}",
                                                    result->character_slot_count);
                                            }
                                            state->data_coordination_started.store(false,
                                                                                   std::memory_order_release);
                                        });
        }
        REXLOG_INFO("Lobby connect redirected: port={} caller={:08X}",
                    state->view_port,
                    caller);
    };
    config.network_hooks.before_send =
        [state](uint32_t caller, uint16_t peer_port, std::span<uint8_t> bytes)
    {
        std::vector<uint8_t> prepared;
        if (!revana::login::PrepareLobbySend(
                bytes, peer_port, state->data_port, state->view_port, state->session.session_hash, state->client_version, prepared))
        {
            return;
        }
        std::copy(prepared.begin(), prepared.end(), bytes.begin());
        const uint32_t command = ReadLe32(bytes, 8);
        SecureZeroMemory(prepared.data(), prepared.size());
        REXLOG_INFO(
            "Lobby send authenticated: command={:02X} size={} port={} caller={:08X}",
            command,
            bytes.size(),
            peer_port,
            caller);
    };
    config.network_hooks.consume_send =
        [state](uint32_t caller, uint16_t peer_port, std::span<const uint8_t> bytes)
    {
        if (peer_port != state->view_port || bytes.size() != 152 ||
            ReadLe32(bytes, 8) != 0x26 ||
            !state->bootstrap_view_login_pending.exchange(
                false, std::memory_order_acq_rel))
        {
            return false;
        }
        REXLOG_INFO(
            "Lobby bootstrap consumed duplicate guest command 26: size={} "
            "port={} caller={:08X}",
            bytes.size(),
            peer_port,
            caller);
        return true;
    };

    RevanaSetGuestTraceHooksEnabled(state_trace_enabled_);
    REXLOG_INFO("Lobby bridge authenticated; Xbox guest networking enabled");
    return true;
}

std::optional<uint32_t> RevanaLobbyBridge::configured_ipv4() const
{
    if (!state_)
    {
        return std::nullopt;
    }
    return state_->ipv4;
}

void RevanaLobbyBridge::StartStateTrace(rex::Runtime* runtime)
{
    if (!state_trace_enabled_ || !runtime || state_trace_thread_.joinable())
    {
        return;
    }

    state_trace_thread_ = std::jthread([runtime](std::stop_token stop)
                                       {
                                           constexpr uint32_t kLobbyModuleSentinel = 0x841ACC88;
                                           constexpr size_t   kMaximumChanges      = 128;

                                           while (!stop.stop_requested() &&
                                                  !runtime->function_dispatcher()->GetFunction(kLobbyModuleSentinel))
                                           {
                                               std::this_thread::yield();
                                           }
                                           if (stop.stop_requested())
                                           {
                                               return;
                                           }

                                           while (!stop.stop_requested() &&
                                                  !RevanaGuestLobbyControllerReady())
                                           {
                                               std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                           }
                                           if (stop.stop_requested())
                                           {
                                               return;
                                           }

                                           REXLOG_INFO("Xbox lobby control trace armed");
                                           const uint32_t                   object = RevanaGuestLobbyControllerObject();
                                           std::optional<LobbyControlState> previous;
                                           size_t                           changes = 0;
                                           while (!stop.stop_requested() && changes < kMaximumChanges)
                                           {
                                               const auto current = ReadLobbyControlState(runtime->memory(), object);
                                               if (current && (!previous || *current != *previous))
                                               {
                                                   REXLOG_INFO(
                                                       "Xbox lobby control state: init_started={} init_count={} offset8={} "
                                                       "offset12={} offset20={} offset136={} offset140={} offset144={} "
                                                       "offset152={}",
                                                       current->initialization_started,
                                                       current->initialization_count,
                                                       current->update_stage,
                                                       current->flow_state,
                                                       current->flow_condition,
                                                       current->current_state,
                                                       current->prior_state,
                                                       current->readiness_state,
                                                       current->active);
                                                   previous = current;
                                                   ++changes;
                                               }
                                               std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                           }
                                           if (changes == kMaximumChanges)
                                           {
                                               REXLOG_INFO("Xbox lobby control trace reached its change limit");
                                           }
                                       });
}

void RevanaLobbyBridge::StopStateTrace()
{
    RevanaSetGuestTraceHooksEnabled(false);
    if (state_trace_thread_.joinable())
    {
        state_trace_thread_.request_stop();
        state_trace_thread_.join();
    }
}
