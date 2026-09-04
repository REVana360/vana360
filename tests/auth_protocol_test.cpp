#include <login/auth_protocol.h>

#include <algorithm>
#include <cassert>
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
    assert(request);
    assert(IsCompleteJson(*request));
    assert(request->find("\"command\":16") != std::string::npos);
    assert(request->find("\"version\":[2,1,0]") != std::string::npos);
    assert(request->find("\"client_profile\":\"july-2009-xbox\"") != std::string::npos);
    assert(request->find("p\\\"ass\\\\word") != std::string::npos);

    const auto session = DecodeLoginResponse(
        R"({"account_id":1000,"result":1,"session_hash":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]})");
    assert(session);
    assert(session->account_id == 1000);
    for (uint8_t i = 0; i < session->session_hash.size(); ++i)
    {
        assert(session->session_hash[i] == i);
    }

    const auto rejected = DecodeLoginResponse(R"({"result":2})");
    assert(!rejected);
    assert(rejected.error().error == AuthError::kServerRejected);
    assert(rejected.error().server_result == 2);

    const auto version_rejected =
        DecodeLoginResponse(R"({"error_message":"unsupported version"})");
    assert(!version_rejected);
    assert(version_rejected.error().error == AuthError::kServerRejected);
    assert(!version_rejected.error().server_result);

    const auto malformed_hash = DecodeLoginResponse(
        R"({"account_id":1000,"result":1,"session_hash":[0,1,2]})");
    assert(!malformed_hash);
    assert(malformed_hash.error().error == AuthError::kMalformedResponse);

    const AuthCredentials long_username{
        .username = std::string(17, 'a'),
        .password = "password",
        .otp      = "",
    };
    const auto invalid_request = EncodeLoginAttempt(long_username);
    assert(!invalid_request);
    assert(invalid_request.error().error == AuthError::kInvalidInput);

    const AuthCredentials embedded_null{
        .username = std::string("a\0b", 3),
        .password = "password",
        .otp      = "",
    };
    const auto invalid_null = EncodeLoginAttempt(embedded_null);
    assert(!invalid_null);
    assert(invalid_null.error().error == AuthError::kInvalidInput);

    const auto oversized_result =
        DecodeLoginResponse(R"({"result":18446744073709551615})");
    assert(!oversized_result);
    assert(oversized_result.error().error == AuthError::kMalformedResponse);

    const auto invalid_host = Authenticate("", credentials);
    assert(!invalid_host);
    assert(invalid_host.error().error == AuthError::kInvalidInput);
}
