#pragma once

#include <login/auth_client.h>

#include <cstdint>
#include <expected>
#include <optional>
#include <stop_token>
#include <string_view>

namespace revana::login
{

inline constexpr uint16_t kLoginDataPort = 54230;
inline constexpr uint16_t kLoginViewPort = 54001;

struct LobbyOptions
{
    uint16_t data_port            = kLoginDataPort;
    uint16_t view_port            = kLoginViewPort;
    uint32_t timeout_ms           = 10000;
    uint32_t selection_timeout_ms = 300000;
};

enum class LobbyStage
{
    kInput,
    kResolve,
    kConnect,
    kDataBind,
    kViewLogin,
    kViewCharacterRequest,
    kDataTrigger,
    kDataAccountRequest,
    kDataCharacterList,
    kViewCharacterList,
    kDataSelectionTrigger,
    kDataSelectionRequest,
};

enum class LobbyError
{
    kInvalidInput,
    kNameResolutionFailed,
    kConnectionFailed,
    kIoFailed,
    kResponseTooLarge,
    kUnexpectedResponse,
    kMalformedResponse,
    kCancelled,
    kTimedOut,
};

struct LobbyFailure
{
    LobbyError                error = LobbyError::kMalformedResponse;
    LobbyStage                stage = LobbyStage::kInput;
    std::optional<ParseError> parse_error;
};

struct DataCharacterLoginResult
{
    uint8_t character_slot_count = 0;
};

// Own the lobby data socket while the guest owns the lobby view socket. This
// blocks across the guest's 0x1F list request and 0x07 character selection so
// both exchanges use the same server-side data session.
std::expected<DataCharacterLoginResult, LobbyFailure>
CoordinateCharacterLoginData(std::string_view host, const AuthSession& session, const MapSessionKey& map_session_key, std::stop_token stop_token, const LobbyOptions& options = {});

std::expected<CharacterList, LobbyFailure>
FetchCharacterSummaries(std::string_view host, const AuthSession& session, const ClientVersion& client_version, const LobbyOptions& options = {});

} // namespace revana::login
