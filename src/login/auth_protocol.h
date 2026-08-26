#pragma once

#include <login/auth_client.h>

#include <expected>
#include <string>
#include <string_view>

namespace revana::login::detail
{

std::expected<std::string, AuthFailure>
EncodeLoginAttempt(const AuthCredentials& credentials);

std::expected<AuthSession, AuthFailure>
DecodeLoginResponse(std::string_view response);

bool IsCompleteJson(std::string_view input);

} // namespace revana::login::detail
