#define NOMINMAX

#include <winsock2.h>

#include <windows.h>

#include <ws2tcpip.h>

#include <login/lobby_client.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <span>
#include <thread>
#include <utility>
#include <vector>

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
    assert(listener);

    sockaddr_in address{};
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port        = 0;
    assert(bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0);
    assert(listen(listener.get(), 1) == 0);

    int address_size = sizeof(address);
    assert(getsockname(listener.get(), reinterpret_cast<sockaddr*>(&address), &address_size) == 0);
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
        assert(offset + fragment_size <= bytes.size());
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

void WriteLe32(std::span<uint8_t> bytes, size_t offset, uint32_t value)
{
    bytes[offset + 0] = static_cast<uint8_t>(value);
    bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
    bytes[offset + 2] = static_cast<uint8_t>(value >> 16);
    bytes[offset + 3] = static_cast<uint8_t>(value >> 24);
}

void ApplyIdentifier(std::span<uint8_t> bytes)
{
    const auto identifier = revana::login::CalculateLobbyIdentifier(bytes);
    assert(identifier);
    std::copy(identifier->begin(), identifier->end(), bytes.begin() + 12);
}

struct MockExchange
{
    revana::login::SessionMaterial session;
    revana::login::ClientVersion   client_version;
    bool                           tamper_character_list   = false;
    bool                           truncate_character_list = false;
    bool                           succeeded               = false;
};

void ServeLobby(SOCKET data_listener, SOCKET view_listener, MockExchange& exchange)
{
    SocketHandle data(accept(data_listener, nullptr, nullptr));
    SocketHandle view(accept(view_listener, nullptr, nullptr));
    if (!data || !view)
    {
        return;
    }

    std::array<uint8_t, revana::login::kDataRequestSize> data_bind{};
    if (!ReceiveExact(data.get(), data_bind) || data_bind[0] != 0xFE ||
        !std::equal(exchange.session.session_hash.begin(),
                    exchange.session.session_hash.end(),
                    data_bind.begin() + 12))
    {
        return;
    }

    std::array<uint8_t, revana::login::kViewLoginSize> view_login{};
    if (!ReceiveExact(view.get(), view_login) ||
        ReadLe32(view_login, 8) != 0x26 ||
        !std::equal(exchange.session.session_hash.begin(),
                    exchange.session.session_hash.end(),
                    view_login.begin() + 12) ||
        !std::equal(exchange.client_version.begin(),
                    exchange.client_version.end(),
                    view_login.begin() + 116))
    {
        return;
    }

    std::array<uint8_t, revana::login::kKeyResponseSize> key_packet{};
    WriteLe32(key_packet, 0, key_packet.size());
    WriteLe32(key_packet, 4, revana::login::kLobbyTerminator);
    WriteLe32(key_packet, 8, 0x05);
    WriteLe32(key_packet, 28, 0xAD5DE04F);
    WriteLe32(key_packet, 32, 0x01020304);
    WriteLe32(key_packet, 36, 0x05060708);
    ApplyIdentifier(key_packet);
    constexpr std::array<size_t, 3> kKeyFragments{ 3, 8, 5 };
    if (!SendFragments(view.get(), key_packet, kKeyFragments))
    {
        return;
    }

    std::array<uint8_t, revana::login::kViewCharacterRequestSize>
        character_request{};
    if (!ReceiveExact(view.get(), character_request) ||
        ReadLe32(character_request, 8) != 0x1F ||
        !std::equal(exchange.session.session_hash.begin(),
                    exchange.session.session_hash.end(),
                    character_request.begin() + 12))
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
        ReadLe32(account_request, 1) != exchange.session.account_id ||
        !std::equal(exchange.session.session_hash.begin(),
                    exchange.session.session_hash.end(),
                    account_request.begin() + 12))
    {
        return;
    }
    constexpr std::array<uint8_t, 4> kLoopback{ 127, 0, 0, 1 };
    if (!std::equal(kLoopback.begin(), kLoopback.end(), account_request.begin() + 5))
    {
        return;
    }

    std::array<uint8_t, 0x148> loader_list{};
    loader_list[0] = 0x03;
    loader_list[1] = 1;
    WriteLe32(loader_list, 16, 0x00123456);
    constexpr std::array<size_t, 3> kLoaderFragments{ 1, 17, 41 };
    if (!SendFragments(data.get(), loader_list, kLoaderFragments))
    {
        return;
    }

    std::array<uint8_t, 0xAC> character_packet{};
    WriteLe32(character_packet, 0, character_packet.size());
    WriteLe32(character_packet, 4, revana::login::kLobbyTerminator);
    WriteLe32(character_packet, 8, 0x20);
    WriteLe32(character_packet, 28, 1);
    WriteLe32(character_packet, 32, 0x00123456);
    character_packet[40]            = 1;
    constexpr char kCharacterName[] = "Testchar";
    std::copy_n(kCharacterName, sizeof(kCharacterName), character_packet.begin() + 44);
    ApplyIdentifier(character_packet);
    if (exchange.tamper_character_list)
    {
        character_packet[44] ^= 1;
    }
    constexpr std::array<size_t, 4> kCharacterFragments{ 2, 3, 23, 61 };
    const size_t                    character_size =
        character_packet.size() - (exchange.truncate_character_list ? 1 : 0);
    if (!SendFragments(view.get(),
                       std::span(character_packet).first(character_size),
                       kCharacterFragments))
    {
        return;
    }
    if (exchange.truncate_character_list)
    {
        shutdown(view.get(), SD_SEND);
    }

    exchange.succeeded = true;
}

std::expected<revana::login::CharacterList, revana::login::LobbyFailure>
RunExchange(const WinsockRuntime& winsock, bool tamper_character_list, bool truncate_character_list, bool& server_succeeded)
{
    assert(winsock.ready());
    auto data_listener = CreateListener();
    auto view_listener = CreateListener();

    revana::login::SessionHash session_hash{};
    for (uint8_t i = 0; i < session_hash.size(); ++i)
    {
        session_hash[i] = static_cast<uint8_t>(i + 1);
    }
    MockExchange exchange{
        .session =
            revana::login::SessionMaterial{
                .account_id   = 0x78563412,
                .session_hash = session_hash,
            },
        .client_version =
            revana::login::ClientVersion{ '3', '0', '2', '6', '0', '6', '0', '4', '_', '0' },
        .tamper_character_list   = tamper_character_list,
        .truncate_character_list = truncate_character_list,
    };

    std::jthread server([&]
                        {
                            ServeLobby(data_listener.socket.get(), view_listener.socket.get(), exchange);
                        });

    const auto result = revana::login::FetchCharacterSummaries(
        "127.0.0.1", exchange.session, exchange.client_version, revana::login::LobbyOptions{
                                                                    .data_port  = data_listener.port,
                                                                    .view_port  = view_listener.port,
                                                                    .timeout_ms = 2000,
                                                                });
    server.join();
    server_succeeded = exchange.succeeded;
    return result;
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
    assert(winsock.ready());
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
    assert(winsock.ready());

    bool       server_succeeded = false;
    const auto result           = RunExchange(winsock, false, false, server_succeeded);
    assert(server_succeeded);
    assert(result);
    assert(result->characters.size() == 1);
    assert(result->characters[0].content_id == 0x00123456);
    assert(result->characters[0].status == 1);
    assert(result->characters[0].name == "Testchar");

    const auto tampered = RunExchange(winsock, true, false, server_succeeded);
    assert(server_succeeded);
    assert(!tampered);
    assert(tampered.error().error == LobbyError::kMalformedResponse);
    assert(tampered.error().stage == LobbyStage::kViewCharacterList);
    assert(tampered.error().parse_error == ParseError::kInvalidIdentifier);

    const auto truncated = RunExchange(winsock, false, true, server_succeeded);
    assert(server_succeeded);
    assert(!truncated);
    assert(truncated.error().error == LobbyError::kIoFailed);
    assert(truncated.error().stage == LobbyStage::kViewCharacterList);

    const auto data_only =
        RunDataOnlyExchange(winsock, true, 2000, server_succeeded);
    assert(server_succeeded);
    assert(data_only);
    assert(data_only->character_slot_count == 1);

    const auto selection_timeout =
        RunDataOnlyExchange(winsock, false, 50, server_succeeded);
    assert(server_succeeded);
    assert(!selection_timeout);
    assert(selection_timeout.error().error == LobbyError::kTimedOut);
    assert(selection_timeout.error().stage == LobbyStage::kDataSelectionTrigger);

    SessionMaterial invalid_session{};
    ClientVersion   invalid_version{};
    const auto      invalid =
        FetchCharacterSummaries("", invalid_session, invalid_version);
    assert(!invalid);
    assert(invalid.error().error == LobbyError::kInvalidInput);
}
