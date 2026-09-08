#define NOMINMAX

#include <winsock2.h>

#include <windows.h>

#include <ws2tcpip.h>

#include <login/lobby_client.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace revana::login
{
namespace
{

constexpr size_t kDataTriggerSize         = 5;
constexpr size_t kLoaderCharacterListSize = 0x148;

LobbyFailure Failure(LobbyError error, LobbyStage stage, std::optional<ParseError> parse_error = std::nullopt)
{
    return LobbyFailure{
        .error       = error,
        .stage       = stage,
        .parse_error = parse_error,
    };
}

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

template <size_t Size>
class SensitiveArray
{
public:
    explicit SensitiveArray(std::array<uint8_t, Size> value)
    : value_(std::move(value))
    {
    }

    SensitiveArray(const SensitiveArray&)            = delete;
    SensitiveArray& operator=(const SensitiveArray&) = delete;

    ~SensitiveArray()
    {
        SecureZeroMemory(value_.data(), value_.size());
    }

    std::span<const uint8_t> bytes() const
    {
        return value_;
    }

private:
    std::array<uint8_t, Size> value_;
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

bool ConnectSocket(SOCKET socket, const sockaddr_in& address, uint32_t timeout_ms)
{
    u_long nonblocking = 1;
    if (ioctlsocket(socket, FIONBIO, &nonblocking) != 0)
    {
        return false;
    }

    const int result = connect(
        socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
    const bool connected = result == 0 || (WSAGetLastError() == WSAEWOULDBLOCK &&
                                           WaitForConnect(socket, timeout_ms));

    nonblocking = 0;
    if (ioctlsocket(socket, FIONBIO, &nonblocking) != 0)
    {
        return false;
    }
    if (!connected)
    {
        return false;
    }

    const DWORD timeout = timeout_ms;
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0 &&
           setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0;
}

std::expected<std::vector<sockaddr_in>, LobbyFailure>
ResolveIpv4(std::string_view host)
{
    const std::string host_string(host);

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* addresses = nullptr;
    if (getaddrinfo(host_string.c_str(), nullptr, &hints, &addresses) != 0)
    {
        return std::unexpected(
            Failure(LobbyError::kNameResolutionFailed, LobbyStage::kResolve));
    }

    std::vector<sockaddr_in> result;
    for (const addrinfo* address = addresses; address != nullptr;
         address                 = address->ai_next)
    {
        if (address->ai_addrlen == sizeof(sockaddr_in))
        {
            result.push_back(
                *reinterpret_cast<const sockaddr_in*>(address->ai_addr));
        }
    }
    freeaddrinfo(addresses);

    if (result.empty())
    {
        return std::unexpected(
            Failure(LobbyError::kNameResolutionFailed, LobbyStage::kResolve));
    }
    return result;
}

std::expected<std::pair<SocketHandle, sockaddr_in>, LobbyFailure>
OpenDataSocket(std::span<const sockaddr_in> addresses,
               const LobbyOptions&          options)
{
    for (auto address : addresses)
    {
        address.sin_port = htons(options.data_port);
        SocketHandle data(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (data && ConnectSocket(data.get(), address, options.timeout_ms))
        {
            return std::pair{ std::move(data), address };
        }
    }

    return std::unexpected(
        Failure(LobbyError::kConnectionFailed, LobbyStage::kConnect));
}

bool SendAll(SOCKET socket, std::span<const uint8_t> bytes)
{
    while (!bytes.empty())
    {
        const size_t chunk_size = std::min(
            bytes.size(), static_cast<size_t>(std::numeric_limits<int>::max()));
        const int sent = send(socket, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(chunk_size), 0);
        if (sent <= 0)
        {
            return false;
        }
        bytes = bytes.subspan(static_cast<size_t>(sent));
    }
    return true;
}

bool ReceiveExact(SOCKET socket, std::span<uint8_t> bytes)
{
    while (!bytes.empty())
    {
        const size_t chunk_size = std::min(
            bytes.size(), static_cast<size_t>(std::numeric_limits<int>::max()));
        const int received = recv(socket, reinterpret_cast<char*>(bytes.data()), static_cast<int>(chunk_size), 0);
        if (received <= 0)
        {
            return false;
        }
        bytes = bytes.subspan(static_cast<size_t>(received));
    }
    return true;
}

enum class ReceiveWaitResult
{
    kComplete,
    kCancelled,
    kTimedOut,
    kIoFailed,
};

ReceiveWaitResult ReceiveExactUntil(SOCKET socket, std::span<uint8_t> bytes, std::stop_token stop_token, uint32_t timeout_ms)
{
    constexpr DWORD kPollTimeoutMs = 100;
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&kPollTimeoutMs), sizeof(kPollTimeoutMs)) != 0)
    {
        return ReceiveWaitResult::kIoFailed;
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (!bytes.empty())
    {
        if (stop_token.stop_requested())
        {
            return ReceiveWaitResult::kCancelled;
        }
        if (std::chrono::steady_clock::now() >= deadline)
        {
            return ReceiveWaitResult::kTimedOut;
        }

        const size_t chunk_size = std::min(
            bytes.size(), static_cast<size_t>(std::numeric_limits<int>::max()));
        const int received = recv(socket, reinterpret_cast<char*>(bytes.data()), static_cast<int>(chunk_size), 0);
        if (received > 0)
        {
            bytes = bytes.subspan(static_cast<size_t>(received));
            continue;
        }
        if (received == 0)
        {
            return ReceiveWaitResult::kIoFailed;
        }
        const int error = WSAGetLastError();
        if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK)
        {
            return ReceiveWaitResult::kIoFailed;
        }
    }
    return ReceiveWaitResult::kComplete;
}

Ipv4Address ToIpv4Address(const sockaddr_in& address)
{
    Ipv4Address result{};
    const auto* bytes =
        reinterpret_cast<const uint8_t*>(&address.sin_addr.s_addr);
    std::copy_n(bytes, result.size(), result.begin());
    return result;
}

} // namespace

std::expected<DataCharacterLoginResult, LobbyFailure>
CoordinateCharacterLoginData(std::string_view host, const AuthSession& session, const MapSessionKey& map_session_key, std::stop_token stop_token, const LobbyOptions& options)
{
    const bool hash_valid =
        std::any_of(session.session_hash.begin(), session.session_hash.end(), [](uint8_t value)
                    {
                        return value != 0;
                    });
    const bool map_key_valid =
        std::any_of(map_session_key.begin(), map_session_key.end(), [](uint8_t value)
                    {
                        return value != 0;
                    });
    if (host.empty() || session.account_id == 0 || !hash_valid ||
        !map_key_valid || options.data_port == 0 || options.timeout_ms == 0 ||
        options.selection_timeout_ms == 0)
    {
        return std::unexpected(
            Failure(LobbyError::kInvalidInput, LobbyStage::kInput));
    }

    const WinsockRuntime winsock;
    if (!winsock.ready())
    {
        return std::unexpected(
            Failure(LobbyError::kConnectionFailed, LobbyStage::kConnect));
    }

    auto addresses = ResolveIpv4(host);
    if (!addresses)
    {
        return std::unexpected(addresses.error());
    }
    auto data_socket = OpenDataSocket(*addresses, options);
    if (!data_socket)
    {
        return std::unexpected(data_socket.error());
    }

    SensitiveArray data_bind(MakeDataBind(session.session_hash));
    if (!SendAll(data_socket->first.get(), data_bind.bytes()))
    {
        return std::unexpected(
            Failure(LobbyError::kIoFailed, LobbyStage::kDataBind));
    }

    std::array<uint8_t, kDataTriggerSize> data_trigger{};
    if (!ReceiveExact(data_socket->first.get(), data_trigger))
    {
        return std::unexpected(
            Failure(LobbyError::kIoFailed, LobbyStage::kDataTrigger));
    }
    if (data_trigger[0] != 0x01 ||
        !std::all_of(data_trigger.begin() + 1, data_trigger.end(), [](uint8_t value)
                     {
                         return value == 0;
                     }))
    {
        return std::unexpected(
            Failure(LobbyError::kUnexpectedResponse, LobbyStage::kDataTrigger));
    }

    const Ipv4Address server_address = ToIpv4Address(data_socket->second);
    SensitiveArray    account_request(
        MakeDataAccountRequest(session, server_address));
    if (!SendAll(data_socket->first.get(), account_request.bytes()))
    {
        return std::unexpected(
            Failure(LobbyError::kIoFailed, LobbyStage::kDataAccountRequest));
    }

    std::array<uint8_t, kLoaderCharacterListSize> loader_list{};
    if (!ReceiveExact(data_socket->first.get(), loader_list))
    {
        SecureZeroMemory(loader_list.data(), loader_list.size());
        return std::unexpected(
            Failure(LobbyError::kIoFailed, LobbyStage::kDataCharacterList));
    }
    if (loader_list[0] != 0x03 || loader_list[1] > 16)
    {
        SecureZeroMemory(loader_list.data(), loader_list.size());
        return std::unexpected(Failure(LobbyError::kUnexpectedResponse,
                                       LobbyStage::kDataCharacterList));
    }

    const DataCharacterLoginResult result{
        .character_slot_count = loader_list[1],
    };
    SecureZeroMemory(loader_list.data(), loader_list.size());

    data_trigger.fill(0);
    const ReceiveWaitResult selection_trigger = ReceiveExactUntil(
        data_socket->first.get(), data_trigger, stop_token, options.selection_timeout_ms);
    if (selection_trigger != ReceiveWaitResult::kComplete)
    {
        LobbyError error = LobbyError::kIoFailed;
        if (selection_trigger == ReceiveWaitResult::kCancelled)
        {
            error = LobbyError::kCancelled;
        }
        else if (selection_trigger == ReceiveWaitResult::kTimedOut)
        {
            error = LobbyError::kTimedOut;
        }
        return std::unexpected(Failure(error, LobbyStage::kDataSelectionTrigger));
    }
    if (data_trigger[0] != 0x02 ||
        !std::all_of(data_trigger.begin() + 1, data_trigger.end(), [](uint8_t value)
                     {
                         return value == 0;
                     }))
    {
        return std::unexpected(Failure(LobbyError::kUnexpectedResponse,
                                       LobbyStage::kDataSelectionTrigger));
    }

    SensitiveArray selection_request(MakeDataSelectionRequest(map_session_key));
    if (!SendAll(data_socket->first.get(), selection_request.bytes()))
    {
        return std::unexpected(
            Failure(LobbyError::kIoFailed, LobbyStage::kDataSelectionRequest));
    }
    return result;
}

} // namespace revana::login
