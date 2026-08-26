#define SECURITY_WIN32
#define NOMINMAX
#define SCHANNEL_USE_BLACKLISTS

#include <winsock2.h>

#include <windows.h>

#include <winternl.h>

#include <schannel.h>
#include <security.h>
#include <ws2tcpip.h>

#include <login/auth_client.h>

#include "auth_protocol.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace revana::login
{
namespace
{

constexpr size_t kReceiveChunkSize     = 16 * 1024;
constexpr size_t kMaximumEncryptedSize = 1024 * 1024;
constexpr size_t kMaximumResponseSize  = 16 * 1024;
constexpr DWORD  kTlsRequestFlags =
    ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
    ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

AuthFailure Failure(AuthError error)
{
    return AuthFailure{ .error = error, .server_result = std::nullopt };
}

class SensitiveString
{
public:
    explicit SensitiveString(std::string value)
    : value_(std::move(value))
    {
    }

    SensitiveString(const SensitiveString&)            = delete;
    SensitiveString& operator=(const SensitiveString&) = delete;

    ~SensitiveString()
    {
        if (!value_.empty())
        {
            SecureZeroMemory(value_.data(), value_.size());
        }
    }

    std::string& value()
    {
        return value_;
    }

    const std::string& value() const
    {
        return value_;
    }

private:
    std::string value_;
};

class WinsockRuntime
{
public:
    WinsockRuntime()
    {
        WSADATA data{};
        ready_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }

    WinsockRuntime(const WinsockRuntime&)            = delete;
    WinsockRuntime& operator=(const WinsockRuntime&) = delete;

    ~WinsockRuntime()
    {
        if (ready_)
        {
            WSACleanup();
        }
    }

    bool ready() const
    {
        return ready_;
    }

private:
    bool ready_ = false;
};

class SocketHandle
{
public:
    SocketHandle() = default;

    explicit SocketHandle(SOCKET value)
    : value_(value)
    {
    }

    SocketHandle(const SocketHandle&)            = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    SocketHandle(SocketHandle&& other) noexcept
    : value_(std::exchange(other.value_, INVALID_SOCKET))
    {
    }

    SocketHandle& operator=(SocketHandle&& other) noexcept
    {
        if (this != &other)
        {
            Reset();
            value_ = std::exchange(other.value_, INVALID_SOCKET);
        }
        return *this;
    }

    ~SocketHandle()
    {
        Reset();
    }

    SOCKET get() const
    {
        return value_;
    }

    explicit operator bool() const
    {
        return value_ != INVALID_SOCKET;
    }

private:
    void Reset()
    {
        if (value_ != INVALID_SOCKET)
        {
            closesocket(value_);
            value_ = INVALID_SOCKET;
        }
    }

    SOCKET value_ = INVALID_SOCKET;
};

bool WaitForConnect(SOCKET socket, uint32_t timeout_ms)
{
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(socket, &write_set);

    fd_set error_set;
    FD_ZERO(&error_set);
    FD_SET(socket, &error_set);

    timeval timeout{
        .tv_sec  = static_cast<long>(timeout_ms / 1000),
        .tv_usec = static_cast<long>((timeout_ms % 1000) * 1000),
    };
    const int selected = select(0, nullptr, &write_set, &error_set, &timeout);
    if (selected <= 0 || FD_ISSET(socket, &error_set))
    {
        return false;
    }

    int error      = 0;
    int error_size = sizeof(error);
    return getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &error_size) == 0 &&
           error == 0;
}

bool ConnectSocket(SOCKET socket, const sockaddr* address, int address_size, uint32_t timeout_ms)
{
    u_long nonblocking = 1;
    if (ioctlsocket(socket, FIONBIO, &nonblocking) != 0)
    {
        return false;
    }

    const int  result    = connect(socket, address, address_size);
    const bool connected = result == 0 || (WSAGetLastError() == WSAEWOULDBLOCK &&
                                           WaitForConnect(socket, timeout_ms));

    nonblocking = 0;
    if (ioctlsocket(socket, FIONBIO, &nonblocking) != 0)
    {
        return false;
    }
    return connected;
}

std::expected<SocketHandle, AuthFailure>
OpenSocket(std::string_view host, uint16_t port, uint32_t timeout_ms)
{
    const std::string host_string(host);
    const std::string port_string = std::to_string(port);

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* addresses = nullptr;
    if (getaddrinfo(host_string.c_str(), port_string.c_str(), &hints, &addresses) != 0)
    {
        return std::unexpected(Failure(AuthError::kNameResolutionFailed));
    }

    SocketHandle connected;
    for (const addrinfo* address = addresses; address != nullptr;
         address                 = address->ai_next)
    {
        SocketHandle candidate(
            socket(address->ai_family, address->ai_socktype, address->ai_protocol));
        if (!candidate)
        {
            continue;
        }
        if (!ConnectSocket(candidate.get(), address->ai_addr, static_cast<int>(address->ai_addrlen), timeout_ms))
        {
            continue;
        }

        const DWORD timeout = timeout_ms;
        if (setsockopt(candidate.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0 ||
            setsockopt(candidate.get(), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0)
        {
            continue;
        }
        connected = std::move(candidate);
        break;
    }
    freeaddrinfo(addresses);

    if (!connected)
    {
        return std::unexpected(Failure(AuthError::kConnectionFailed));
    }
    return connected;
}

std::expected<std::wstring, AuthFailure> ToWide(std::string_view input)
{
    if (input.empty() || input.size() > std::numeric_limits<int>::max())
    {
        return std::unexpected(Failure(AuthError::kInvalidInput));
    }
    const int required =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (required <= 0)
    {
        return std::unexpected(Failure(AuthError::kInvalidInput));
    }
    std::wstring output(required, L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), required) != required)
    {
        return std::unexpected(Failure(AuthError::kInvalidInput));
    }
    return output;
}

class TlsConnection
{
public:
    explicit TlsConnection(SocketHandle socket)
    : socket_(std::move(socket))
    {
        SecInvalidateHandle(&credentials_);
        SecInvalidateHandle(&context_);
    }

    TlsConnection(const TlsConnection&)            = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;

    ~TlsConnection()
    {
        if (context_ready_)
        {
            DeleteSecurityContext(&context_);
        }
        if (credentials_ready_)
        {
            FreeCredentialsHandle(&credentials_);
        }
    }

    bool Handshake(const std::wstring&                     server_name,
                   const std::optional<CertificateSha256>& certificate_sha256)
    {
        server_name_ = server_name;
        TLS_PARAMETERS tls_parameters{};
        tls_parameters.grbitDisabledProtocols =
            SP_PROT_SSL2_CLIENT | SP_PROT_SSL3_CLIENT | SP_PROT_TLS1_0_CLIENT |
            SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;

        SCH_CREDENTIALS schannel_credentials{};
        schannel_credentials.dwVersion = SCH_CREDENTIALS_VERSION;
        schannel_credentials.dwFlags =
            (certificate_sha256 ? SCH_CRED_MANUAL_CRED_VALIDATION
                                : SCH_CRED_AUTO_CRED_VALIDATION) |
            SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
        schannel_credentials.cTlsParameters = 1;
        schannel_credentials.pTlsParameters = &tls_parameters;

        TimeStamp       expiry{};
        SECURITY_STATUS status = AcquireCredentialsHandleW(
            nullptr, const_cast<wchar_t*>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND, nullptr, &schannel_credentials, nullptr, nullptr, &credentials_, &expiry);
        if (status != SEC_E_OK)
        {
            return false;
        }
        credentials_ready_ = true;

        SecBuffer output_buffer{
            .cbBuffer   = 0,
            .BufferType = SECBUFFER_TOKEN,
            .pvBuffer   = nullptr,
        };
        SecBufferDesc output{
            .ulVersion = SECBUFFER_VERSION,
            .cBuffers  = 1,
            .pBuffers  = &output_buffer,
        };
        DWORD attributes = 0;
        status           = InitializeSecurityContextW(
            &credentials_, nullptr, const_cast<wchar_t*>(server_name.c_str()), kTlsRequestFlags, 0, SECURITY_NATIVE_DREP, nullptr, 0, &context_, &output, &attributes, &expiry);
        context_ready_ = SecIsValidHandle(&context_) != FALSE;
        if (!CompleteAndSend(status, output, output_buffer))
        {
            return false;
        }
        status = NormalizeCompleteStatus(status);
        if (status != SEC_I_CONTINUE_NEEDED)
        {
            return false;
        }

        std::vector<uint8_t> encrypted;
        if (!ContinueHandshake(encrypted))
        {
            return false;
        }
        if (certificate_sha256 && !ValidateCertificatePin(*certificate_sha256))
        {
            return false;
        }
        return true;
    }

    bool Send(std::span<const uint8_t> plaintext)
    {
        if (plaintext.empty() ||
            plaintext.size() > stream_sizes_.cbMaximumMessage ||
            plaintext.size() > std::numeric_limits<unsigned long>::max())
        {
            return false;
        }

        std::vector<uint8_t> record(stream_sizes_.cbHeader + plaintext.size() +
                                    stream_sizes_.cbTrailer);
        std::copy(plaintext.begin(), plaintext.end(), record.begin() + stream_sizes_.cbHeader);

        std::array<SecBuffer, 4> buffers{
            SecBuffer{
                .cbBuffer   = stream_sizes_.cbHeader,
                .BufferType = SECBUFFER_STREAM_HEADER,
                .pvBuffer   = record.data(),
            },
            SecBuffer{
                .cbBuffer   = static_cast<unsigned long>(plaintext.size()),
                .BufferType = SECBUFFER_DATA,
                .pvBuffer   = record.data() + stream_sizes_.cbHeader,
            },
            SecBuffer{
                .cbBuffer   = stream_sizes_.cbTrailer,
                .BufferType = SECBUFFER_STREAM_TRAILER,
                .pvBuffer =
                    record.data() + stream_sizes_.cbHeader + plaintext.size(),
            },
            SecBuffer{
                .cbBuffer   = 0,
                .BufferType = SECBUFFER_EMPTY,
                .pvBuffer   = nullptr,
            },
        };
        SecBufferDesc message{
            .ulVersion = SECBUFFER_VERSION,
            .cBuffers  = static_cast<unsigned long>(buffers.size()),
            .pBuffers  = buffers.data(),
        };
        if (EncryptMessage(&context_, 0, &message, 0) != SEC_E_OK)
        {
            SecureZeroMemory(record.data(), record.size());
            return false;
        }
        const bool sent =
            SendAll(std::span(static_cast<const uint8_t*>(buffers[0].pvBuffer),
                              buffers[0].cbBuffer)) &&
            SendAll(std::span(static_cast<const uint8_t*>(buffers[1].pvBuffer),
                              buffers[1].cbBuffer)) &&
            SendAll(std::span(static_cast<const uint8_t*>(buffers[2].pvBuffer),
                              buffers[2].cbBuffer));
        SecureZeroMemory(record.data(), record.size());
        return sent;
    }

    std::expected<std::string, AuthFailure> ReceiveJson()
    {
        std::vector<uint8_t> encrypted = std::move(pending_encrypted_);
        std::string          plaintext;

        while (plaintext.size() <= kMaximumResponseSize)
        {
            if (encrypted.empty() && !Receive(encrypted))
            {
                return std::unexpected(Failure(plaintext.empty()
                                                   ? AuthError::kIoFailed
                                                   : AuthError::kMalformedResponse));
            }

            std::array<SecBuffer, 4> buffers{
                SecBuffer{
                    .cbBuffer   = static_cast<unsigned long>(encrypted.size()),
                    .BufferType = SECBUFFER_DATA,
                    .pvBuffer   = encrypted.data(),
                },
                SecBuffer{
                    .cbBuffer   = 0,
                    .BufferType = SECBUFFER_EMPTY,
                    .pvBuffer   = nullptr,
                },
                SecBuffer{
                    .cbBuffer   = 0,
                    .BufferType = SECBUFFER_EMPTY,
                    .pvBuffer   = nullptr,
                },
                SecBuffer{
                    .cbBuffer   = 0,
                    .BufferType = SECBUFFER_EMPTY,
                    .pvBuffer   = nullptr,
                },
            };
            SecBufferDesc message{
                .ulVersion = SECBUFFER_VERSION,
                .cBuffers  = static_cast<unsigned long>(buffers.size()),
                .pBuffers  = buffers.data(),
            };

            const SECURITY_STATUS status =
                DecryptMessage(&context_, &message, 0, nullptr);
            if (status == SEC_E_INCOMPLETE_MESSAGE)
            {
                if (!Receive(encrypted))
                {
                    return std::unexpected(Failure(AuthError::kIoFailed));
                }
                continue;
            }
            if (status == SEC_I_RENEGOTIATE)
            {
                const auto extra = std::find_if(
                    buffers.begin(), buffers.end(), [](const SecBuffer& buffer)
                    {
                        return buffer.BufferType == SECBUFFER_EXTRA;
                    });
                if (extra == buffers.end())
                {
                    return std::unexpected(Failure(AuthError::kTlsFailed));
                }
                PreserveExtra(encrypted, *extra);
                if (!ContinueHandshake(encrypted))
                {
                    return std::unexpected(Failure(AuthError::kTlsFailed));
                }
                encrypted = std::move(pending_encrypted_);
                continue;
            }
            if (status != SEC_E_OK)
            {
                return std::unexpected(Failure(AuthError::kTlsFailed));
            }

            const SecBuffer* extra = nullptr;
            for (const auto& buffer : buffers)
            {
                if (buffer.BufferType == SECBUFFER_DATA && buffer.cbBuffer != 0)
                {
                    const auto* data = static_cast<const char*>(buffer.pvBuffer);
                    plaintext.append(data, buffer.cbBuffer);
                }
                else if (buffer.BufferType == SECBUFFER_EXTRA)
                {
                    extra = &buffer;
                }
            }
            if (plaintext.size() > kMaximumResponseSize)
            {
                return std::unexpected(Failure(AuthError::kResponseTooLarge));
            }
            if (detail::IsCompleteJson(plaintext))
            {
                return plaintext;
            }

            if (extra != nullptr)
            {
                PreserveExtra(encrypted, *extra);
            }
            else
            {
                encrypted.clear();
            }
        }
        return std::unexpected(Failure(AuthError::kResponseTooLarge));
    }

private:
    bool ContinueHandshake(std::vector<uint8_t>& encrypted)
    {
        while (true)
        {
            if (encrypted.empty() && !Receive(encrypted))
            {
                return false;
            }

            std::array<SecBuffer, 2> input_buffers{
                SecBuffer{
                    .cbBuffer   = static_cast<unsigned long>(encrypted.size()),
                    .BufferType = SECBUFFER_TOKEN,
                    .pvBuffer   = encrypted.data(),
                },
                SecBuffer{
                    .cbBuffer   = 0,
                    .BufferType = SECBUFFER_EMPTY,
                    .pvBuffer   = nullptr,
                },
            };
            SecBufferDesc input{
                .ulVersion = SECBUFFER_VERSION,
                .cBuffers  = static_cast<unsigned long>(input_buffers.size()),
                .pBuffers  = input_buffers.data(),
            };
            SecBuffer output_buffer{
                .cbBuffer   = 0,
                .BufferType = SECBUFFER_TOKEN,
                .pvBuffer   = nullptr,
            };
            SecBufferDesc output{
                .ulVersion = SECBUFFER_VERSION,
                .cBuffers  = 1,
                .pBuffers  = &output_buffer,
            };
            DWORD     attributes = 0;
            TimeStamp expiry{};

            SECURITY_STATUS status = InitializeSecurityContextW(
                &credentials_, &context_, const_cast<wchar_t*>(server_name_.c_str()), kTlsRequestFlags, 0, SECURITY_NATIVE_DREP, &input, 0, nullptr, &output, &attributes, &expiry);
            if (!CompleteAndSend(status, output, output_buffer))
            {
                return false;
            }
            status = NormalizeCompleteStatus(status);
            if (status == SEC_E_INCOMPLETE_MESSAGE)
            {
                if (!Receive(encrypted))
                {
                    return false;
                }
                continue;
            }

            PreserveExtra(encrypted, input_buffers[1]);
            if (status == SEC_E_OK)
            {
                pending_encrypted_ = std::move(encrypted);
                return QueryContextAttributesW(&context_, SECPKG_ATTR_STREAM_SIZES, &stream_sizes_) == SEC_E_OK;
            }
            if (status != SEC_I_CONTINUE_NEEDED)
            {
                return false;
            }
        }
    }

    bool ValidateCertificatePin(const CertificateSha256& expected)
    {
        PCCERT_CONTEXT certificate = nullptr;
        if (QueryContextAttributesW(&context_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &certificate) != SEC_E_OK ||
            certificate == nullptr)
        {
            return false;
        }

        CertificateSha256 actual{};
        DWORD             actual_size = static_cast<DWORD>(actual.size());
        const bool        valid =
            CertGetCertificateContextProperty(certificate, CERT_SHA256_HASH_PROP_ID, actual.data(), &actual_size) != FALSE &&
            actual_size == actual.size() &&
            std::equal(actual.begin(), actual.end(), expected.begin());
        CertFreeCertificateContext(certificate);
        return valid;
    }

    static SECURITY_STATUS NormalizeCompleteStatus(SECURITY_STATUS status)
    {
        if (status == SEC_I_COMPLETE_NEEDED)
        {
            return SEC_E_OK;
        }
        if (status == SEC_I_COMPLETE_AND_CONTINUE)
        {
            return SEC_I_CONTINUE_NEEDED;
        }
        return status;
    }

    bool CompleteAndSend(SECURITY_STATUS status, SecBufferDesc& output, SecBuffer& output_buffer)
    {
        if ((status == SEC_I_COMPLETE_NEEDED ||
             status == SEC_I_COMPLETE_AND_CONTINUE) &&
            CompleteAuthToken(&context_, &output) != SEC_E_OK)
        {
            if (output_buffer.pvBuffer != nullptr)
            {
                FreeContextBuffer(output_buffer.pvBuffer);
            }
            return false;
        }

        bool sent = true;
        if (output_buffer.pvBuffer != nullptr && output_buffer.cbBuffer != 0)
        {
            sent = SendAll(
                std::span(static_cast<const uint8_t*>(output_buffer.pvBuffer),
                          output_buffer.cbBuffer));
        }
        if (output_buffer.pvBuffer != nullptr)
        {
            FreeContextBuffer(output_buffer.pvBuffer);
            output_buffer.pvBuffer = nullptr;
        }
        return sent;
    }

    static void PreserveExtra(std::vector<uint8_t>& encrypted,
                              const SecBuffer&      extra)
    {
        if (extra.BufferType != SECBUFFER_EXTRA || extra.cbBuffer == 0)
        {
            encrypted.clear();
            return;
        }
        const size_t extra_size = extra.cbBuffer;
        std::move(encrypted.end() - extra_size, encrypted.end(), encrypted.begin());
        encrypted.resize(extra_size);
    }

    bool SendAll(std::span<const uint8_t> data)
    {
        while (!data.empty())
        {
            const size_t chunk_size = std::min(
                data.size(), static_cast<size_t>(std::numeric_limits<int>::max()));
            const int sent =
                send(socket_.get(), reinterpret_cast<const char*>(data.data()), static_cast<int>(chunk_size), 0);
            if (sent <= 0)
            {
                return false;
            }
            data = data.subspan(static_cast<size_t>(sent));
        }
        return true;
    }

    bool Receive(std::vector<uint8_t>& encrypted)
    {
        if (encrypted.size() > kMaximumEncryptedSize - kReceiveChunkSize)
        {
            return false;
        }
        std::array<uint8_t, kReceiveChunkSize> buffer{};
        const int                              received =
            recv(socket_.get(), reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
        if (received <= 0)
        {
            return false;
        }
        encrypted.insert(encrypted.end(), buffer.begin(), buffer.begin() + received);
        return true;
    }

    SocketHandle              socket_;
    CredHandle                credentials_{};
    CtxtHandle                context_{};
    bool                      credentials_ready_ = false;
    bool                      context_ready_     = false;
    SecPkgContext_StreamSizes stream_sizes_{};
    std::vector<uint8_t>      pending_encrypted_;
    std::wstring              server_name_;
};

} // namespace

std::expected<AuthSession, AuthFailure>
Authenticate(std::string_view host, const AuthCredentials& credentials, const AuthOptions& options)
{
    if (host.empty() || options.port == 0 || options.timeout_ms == 0)
    {
        return std::unexpected(Failure(AuthError::kInvalidInput));
    }

    auto encoded = detail::EncodeLoginAttempt(credentials);
    if (!encoded)
    {
        return std::unexpected(encoded.error());
    }
    SensitiveString request(std::move(*encoded));

    const WinsockRuntime winsock;
    if (!winsock.ready())
    {
        return std::unexpected(Failure(AuthError::kConnectionFailed));
    }

    auto socket = OpenSocket(host, options.port, options.timeout_ms);
    if (!socket)
    {
        return std::unexpected(socket.error());
    }
    auto wide_host = ToWide(host);
    if (!wide_host)
    {
        return std::unexpected(wide_host.error());
    }

    TlsConnection connection(std::move(*socket));
    if (!connection.Handshake(*wide_host, options.certificate_sha256))
    {
        return std::unexpected(Failure(AuthError::kTlsFailed));
    }
    const auto request_bytes =
        std::span(reinterpret_cast<const uint8_t*>(request.value().data()),
                  request.value().size());
    if (!connection.Send(request_bytes))
    {
        return std::unexpected(Failure(AuthError::kIoFailed));
    }

    auto response = connection.ReceiveJson();
    if (!response)
    {
        return std::unexpected(response.error());
    }
    SensitiveString sensitive_response(std::move(*response));
    return detail::DecodeLoginResponse(sensitive_response.value());
}

} // namespace revana::login
