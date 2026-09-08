#include <login/auth_protocol.h>

#include "check.h"
#include <algorithm>
#include <string>

int main()
{
    using namespace revana::login;
    using namespace revana::login::detail;

    const AuthCredentials credentials{
        .username = "testuser",
        .password = "p\"ass\\word",
        .otp      = "",
    };
    const auto request = EncodeLoginAttempt(credentials);
    CHECK(request);
    CHECK(IsCompleteJson(*request));
    CHECK(request->find("\"command\":16") != std::string::npos);
    CHECK(request->find("\"version\":[2,1,0]") != std::string::npos);
    CHECK(request->find("\"client_profile\":\"july-2009-xbox\"") != std::string::npos);
    CHECK(request->find("p\\\"ass\\\\word") != std::string::npos);

    const auto session = DecodeLoginResponse(
        R"({"account_id":1000,"result":1,"session_hash":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]})");
    CHECK(session);
    CHECK(session->account_id == 1000);
    for (uint8_t i = 0; i < session->session_hash.size(); ++i)
    {
        CHECK(session->session_hash[i] == i);
    }

    const auto rejected = DecodeLoginResponse(R"({"result":2})");
    CHECK(!rejected);
    CHECK(rejected.error().error == AuthError::kServerRejected);
    CHECK(rejected.error().server_result == 2);

    const auto version_rejected =
        DecodeLoginResponse(R"({"error_message":"unsupported version"})");
    CHECK(!version_rejected);
    CHECK(version_rejected.error().error == AuthError::kServerRejected);
    CHECK(!version_rejected.error().server_result);

    const auto malformed_hash = DecodeLoginResponse(
        R"({"account_id":1000,"result":1,"session_hash":[0,1,2]})");
    CHECK(!malformed_hash);
    CHECK(malformed_hash.error().error == AuthError::kMalformedResponse);

    const AuthCredentials long_username{
        .username = std::string(17, 'a'),
        .password = "password",
        .otp      = "",
    };
    const auto invalid_request = EncodeLoginAttempt(long_username);
    CHECK(!invalid_request);
    CHECK(invalid_request.error().error == AuthError::kInvalidInput);

    const AuthCredentials embedded_null{
        .username = std::string("a\0b", 3),
        .password = "password",
        .otp      = "",
    };
    const auto invalid_null = EncodeLoginAttempt(embedded_null);
    CHECK(!invalid_null);
    CHECK(invalid_null.error().error == AuthError::kInvalidInput);

    const auto oversized_result =
        DecodeLoginResponse(R"({"result":18446744073709551615})");
    CHECK(!oversized_result);
    CHECK(oversized_result.error().error == AuthError::kMalformedResponse);

    const auto invalid_host = Authenticate("", credentials);
    CHECK(!invalid_host);
    CHECK(invalid_host.error().error == AuthError::kInvalidInput);
}
