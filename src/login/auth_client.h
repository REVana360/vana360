#pragma once

#include <login/lobby_packets.h>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace revana::login
{

inline constexpr uint16_t kLoginAuthPort         = 54231;
inline constexpr size_t   kCertificateSha256Size = 32;

using CertificateSha256 = std::array<uint8_t, kCertificateSha256Size>;

struct AuthCredentials
{
    std::string username;
    std::string password;
    std::string otp;
};

struct AuthOptions
{
    uint16_t                         port       = kLoginAuthPort;
    uint32_t                         timeout_ms = 10000;
    std::optional<CertificateSha256> certificate_sha256;
};

using AuthSession = SessionMaterial;

enum class AuthError
{
    kInvalidInput,
    kNameResolutionFailed,
    kConnectionFailed,
    kTlsFailed,
    kIoFailed,
    kResponseTooLarge,
    kMalformedResponse,
    kServerRejected,
};

struct AuthFailure
{
    AuthError              error = AuthError::kMalformedResponse;
    std::optional<uint8_t> server_result;
};

std::expected<AuthSession, AuthFailure>
Authenticate(std::string_view host, const AuthCredentials& credentials, const AuthOptions& options = {});

} // namespace revana::login
