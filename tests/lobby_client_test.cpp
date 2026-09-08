#define NOMINMAX

#include <winsock2.h>

#include <windows.h>

#include <ws2tcpip.h>

#include <login/lobby_client.h>

#include "check.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <span>
#include <thread>
#include <utility>

namespace
{

class WinsockRuntime
{
public:
    WinsockRuntime()
    {
        WSADATA data{};
        ready_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }

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

struct Listener
{
    SocketHandle socket;
    uint16_t     port = 0;
};

Listener CreateListener()
{
    SocketHandle listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    CHECK(listener);

    sockaddr_in address{};
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port        = 0;
    const int bind_result   = bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address));
    CHECK(bind_result == 0);
    const int listen_result = listen(listener.get(), 1);
    CHECK(listen_result == 0);

    int       address_size   = sizeof(address);
    const int address_result = getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &address_size);
    CHECK(address_result == 0);
    return Listener{
        .socket = std::move(listener),
        .port   = ntohs(address.sin_port),
    };
}

bool ReceiveExact(SOCKET socket, std::span<uint8_t> bytes)
{
    while (!bytes.empty())
    {
        const int received = recv(socket, reinterpret_cast<char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
        if (received <= 0)
        {
            return false;
        }
        bytes = bytes.subspan(static_cast<size_t>(received));
    }
    return true;
}

bool SendFragments(SOCKET socket, std::span<const uint8_t> bytes, std::span<const size_t> fragment_sizes)
{
    size_t offset = 0;
    for (const size_t fragment_size : fragment_sizes)
    {
        CHECK(offset + fragment_size <= bytes.size());
        const int sent =
            send(socket, reinterpret_cast<const char*>(bytes.data() + offset), static_cast<int>(fragment_size), 0);
        if (sent != fragment_size)
        {
            return false;
        }
        offset += fragment_size;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (offset == bytes.size())
    {
        return true;
    }
    const size_t remaining = bytes.size() - offset;
    return send(socket, reinterpret_cast<const char*>(bytes.data() + offset), static_cast<int>(remaining), 0) == remaining;
}

uint32_t ReadLe32(std::span<const uint8_t> bytes, size_t offset)
{
    return static_cast<uint32_t>(bytes[offset]) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

void ServeDataOnly(SOCKET                                data_listener,
                   const revana::login::SessionMaterial& session,
                   const revana::login::MapSessionKey&   map_session_key,
                   bool                                  send_selection_trigger,
                   bool&                                 succeeded)
{
    SocketHandle data(accept(data_listener, nullptr, nullptr));
    if (!data)
    {
        return;
    }

    std::array<uint8_t, revana::login::kDataRequestSize> data_bind{};
    if (!ReceiveExact(data.get(), data_bind) || data_bind[0] != 0xFE ||
        !std::equal(session.session_hash.begin(), session.session_hash.end(), data_bind.begin() + 12))
    {
        return;
    }

    constexpr std::array<uint8_t, 5> kDataTrigger{ 1, 0, 0, 0, 0 };
    constexpr std::array<size_t, 1>  kTriggerFragments{ 2 };
    if (!SendFragments(data.get(), kDataTrigger, kTriggerFragments))
    {
        return;
    }

    std::array<uint8_t, revana::login::kDataRequestSize> account_request{};
    if (!ReceiveExact(data.get(), account_request) ||
        account_request[0] != 0xA1 ||
        ReadLe32(account_request, 1) != session.account_id ||
        !std::equal(session.session_hash.begin(), session.session_hash.end(), account_request.begin() + 12))
    {
        return;
    }

    std::array<uint8_t, 0x148> loader_list{};
    loader_list[0] = 0x03;
    loader_list[1] = 1;
    constexpr std::array<size_t, 3> kLoaderFragments{ 1, 17, 41 };
    if (!SendFragments(data.get(), loader_list, kLoaderFragments))
    {
        return;
    }

    if (!send_selection_trigger)
    {
        succeeded = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        return;
    }

    constexpr std::array<uint8_t, 5> kSelectionTrigger{ 2, 0, 0, 0, 0 };
    constexpr std::array<size_t, 2>  kSelectionTriggerFragments{ 1, 2 };
    if (!SendFragments(data.get(), kSelectionTrigger, kSelectionTriggerFragments))
    {
        return;
    }

    std::array<uint8_t, revana::login::kDataRequestSize>
        selection_request{};
    if (!ReceiveExact(data.get(), selection_request) ||
        selection_request[0] != 0xA2 ||
        !std::equal(map_session_key.begin(), map_session_key.end(), selection_request.begin() + 1) ||
        !std::all_of(selection_request.begin() + 21, selection_request.end(), [](uint8_t byte)
                     {
                         return byte == 0;
                     }))
    {
        return;
    }
    succeeded = true;
}

std::expected<revana::login::DataCharacterLoginResult,
              revana::login::LobbyFailure>
RunDataOnlyExchange(const WinsockRuntime& winsock, bool send_selection_trigger, uint32_t selection_timeout_ms, bool& server_succeeded)
{
    CHECK(winsock.ready());
    server_succeeded   = false;
    auto data_listener = CreateListener();

    revana::login::SessionHash session_hash{};
    for (uint8_t i = 0; i < session_hash.size(); ++i)
    {
        session_hash[i] = static_cast<uint8_t>(i + 1);
    }
    const revana::login::SessionMaterial session{
        .account_id   = 0x78563412,
        .session_hash = session_hash,
    };
    revana::login::MapSessionKey map_session_key{};
    for (uint8_t i = 0; i < map_session_key.size(); ++i)
    {
        map_session_key[i] = static_cast<uint8_t>(0x20 + i);
    }

    std::jthread server([&]
                        {
                            ServeDataOnly(data_listener.socket.get(), session, map_session_key, send_selection_trigger, server_succeeded);
                        });
    const auto   result = revana::login::CoordinateCharacterLoginData(
        "127.0.0.1", session, map_session_key, {}, revana::login::LobbyOptions{
                                                       .data_port            = data_listener.port,
                                                       .timeout_ms           = 2000,
                                                       .selection_timeout_ms = selection_timeout_ms,
                                                   });
    server.join();
    return result;
}

} // namespace

int main()
{
    using namespace revana::login;

    const WinsockRuntime winsock;
    CHECK(winsock.ready());

    bool       server_succeeded = false;
    const auto data_only =
        RunDataOnlyExchange(winsock, true, 2000, server_succeeded);
    CHECK(server_succeeded);
    CHECK(data_only);
    CHECK(data_only->character_slot_count == 1);

    const auto selection_timeout =
        RunDataOnlyExchange(winsock, false, 50, server_succeeded);
    CHECK(server_succeeded);
    CHECK(!selection_timeout);
    CHECK(selection_timeout.error().error == LobbyError::kTimedOut);
    CHECK(selection_timeout.error().stage == LobbyStage::kDataSelectionTrigger);

    SessionMaterial invalid_session{};
    MapSessionKey   invalid_key{};
    const auto      invalid =
        CoordinateCharacterLoginData("", invalid_session, invalid_key, {});
    CHECK(!invalid);
    CHECK(invalid.error().error == LobbyError::kInvalidInput);
}
