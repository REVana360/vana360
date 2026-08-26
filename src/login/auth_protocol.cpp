#include "auth_protocol.h"

#include <nlohmann/json.hpp>

#include <limits>

namespace revana::login::detail
{
namespace
{

constexpr uint8_t kLoginAttemptCommand = 0x10;
constexpr uint8_t kLoginSuccess        = 0x01;
constexpr size_t  kMaximumUsernameSize = 16;
constexpr size_t  kMaximumPasswordSize = 32;

AuthFailure Failure(AuthError error)
{
    return AuthFailure{ .error = error, .server_result = std::nullopt };
}

std::optional<uint64_t> ReadUnsigned(const nlohmann::json& value)
{
    if (value.is_number_unsigned())
    {
        return value.get<uint64_t>();
    }
    if (!value.is_number_integer())
    {
        return std::nullopt;
    }
    const auto signed_value = value.get<int64_t>();
    if (signed_value < 0)
    {
        return std::nullopt;
    }
    return static_cast<uint64_t>(signed_value);
}

bool ContainsNull(const std::string& value)
{
    return value.find('\0') != std::string::npos;
}

} // namespace

std::expected<std::string, AuthFailure>
EncodeLoginAttempt(const AuthCredentials& credentials)
{
    if (credentials.username.empty() ||
        credentials.username.size() > kMaximumUsernameSize ||
        credentials.password.empty() ||
        credentials.password.size() > kMaximumPasswordSize ||
        ContainsNull(credentials.username) ||
        ContainsNull(credentials.password) || ContainsNull(credentials.otp))
    {
        return std::unexpected(Failure(AuthError::kInvalidInput));
    }

    nlohmann::json request{
        { "command", kLoginAttemptCommand },
        { "username", credentials.username },
        { "password", credentials.password },
        { "otp", credentials.otp },
        { "new_password", "" },
        { "version", { 2, 1, 0 } },
    };
    return request.dump();
}

std::expected<AuthSession, AuthFailure>
DecodeLoginResponse(std::string_view response)
{
    const auto parsed =
        nlohmann::json::parse(response.begin(), response.end(), nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object())
    {
        return std::unexpected(Failure(AuthError::kMalformedResponse));
    }

    const auto result = parsed.find("result");
    if (result == parsed.end())
    {
        if (parsed.contains("error_message"))
        {
            return std::unexpected(Failure(AuthError::kServerRejected));
        }
        return std::unexpected(Failure(AuthError::kMalformedResponse));
    }

    const auto result_value = ReadUnsigned(*result);
    if (!result_value || *result_value > std::numeric_limits<uint8_t>::max())
    {
        return std::unexpected(Failure(AuthError::kMalformedResponse));
    }
    if (*result_value != kLoginSuccess)
    {
        return std::unexpected(AuthFailure{
            .error         = AuthError::kServerRejected,
            .server_result = static_cast<uint8_t>(*result_value),
        });
    }

    const auto account_id   = parsed.find("account_id");
    const auto session_hash = parsed.find("session_hash");
    if (account_id == parsed.end() || session_hash == parsed.end() ||
        !session_hash->is_array() || session_hash->size() != kSessionHashSize)
    {
        return std::unexpected(Failure(AuthError::kMalformedResponse));
    }

    const auto account_value = ReadUnsigned(*account_id);
    if (!account_value || *account_value == 0 ||
        *account_value > std::numeric_limits<uint32_t>::max())
    {
        return std::unexpected(Failure(AuthError::kMalformedResponse));
    }

    AuthSession session{ .account_id = static_cast<uint32_t>(*account_value) };
    for (size_t i = 0; i < session.session_hash.size(); ++i)
    {
        const auto& value      = (*session_hash)[i];
        const auto  byte_value = ReadUnsigned(value);
        if (!byte_value || *byte_value > std::numeric_limits<uint8_t>::max())
        {
            return std::unexpected(Failure(AuthError::kMalformedResponse));
        }
        session.session_hash[i] = static_cast<uint8_t>(*byte_value);
    }
    return session;
}

bool IsCompleteJson(std::string_view input)
{
    return nlohmann::json::accept(input.begin(), input.end());
}

} // namespace revana::login::detail
