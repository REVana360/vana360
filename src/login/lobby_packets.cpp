#include <windows.h>

#include <bcrypt.h>

#include <login/lobby_packets.h>

#include <algorithm>

namespace revana::login
{
namespace
{

constexpr std::array<uint8_t, 4>  kLobbyMarker{ 'I', 'X', 'F', 'F' };
constexpr std::array<uint32_t, 9> kAuthenticatedLobbyCommands{
    0x07, 0x14, 0x1F, 0x21, 0x22, 0x24, 0x26, 0x28, 0x2B
};

void WriteLe32(std::span<uint8_t> bytes, size_t offset, uint32_t value)
{
    bytes[offset + 0] = static_cast<uint8_t>(value);
    bytes[offset + 1] = static_cast<uint8_t>(value >> 8);
    bytes[offset + 2] = static_cast<uint8_t>(value >> 16);
    bytes[offset + 3] = static_cast<uint8_t>(value >> 24);
}

uint16_t ReadLe16(std::span<const uint8_t> bytes, size_t offset)
{
    return static_cast<uint16_t>(bytes[offset]) |
           static_cast<uint16_t>(bytes[offset + 1] << 8);
}

uint32_t ReadLe32(std::span<const uint8_t> bytes, size_t offset)
{
    return static_cast<uint32_t>(bytes[offset]) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

void CopySessionHash(std::span<uint8_t> bytes,
                     const SessionHash& session_hash)
{
    std::copy(session_hash.begin(), session_hash.end(), bytes.begin() + 12);
}

std::expected<uint32_t, ParseError>
ValidateLobbyHeader(std::span<const uint8_t> bytes, uint32_t expected_command, size_t minimum_size)
{
    if (bytes.size() < minimum_size)
    {
        return std::unexpected(ParseError::kTruncated);
    }

    const uint32_t packet_size = ReadLe32(bytes, 0);
    if (packet_size < minimum_size || packet_size > bytes.size())
    {
        return std::unexpected(ParseError::kInvalidSize);
    }
    if (ReadLe32(bytes, 4) != kLobbyTerminator)
    {
        return std::unexpected(ParseError::kInvalidTerminator);
    }
    if (ReadLe32(bytes, 8) != expected_command)
    {
        return std::unexpected(ParseError::kUnexpectedCommand);
    }
    return packet_size;
}

std::expected<void, ParseError>
ValidateLobbyIdentifier(std::span<const uint8_t> bytes, size_t packet_size)
{
    const auto calculated = CalculateLobbyIdentifier(bytes.first(packet_size));
    if (!calculated)
    {
        return std::unexpected(calculated.error());
    }
    if (!std::equal(calculated->begin(), calculated->end(), bytes.begin() + 12))
    {
        return std::unexpected(ParseError::kInvalidIdentifier);
    }
    return {};
}

bool CalculateMd5(std::span<const uint8_t>             bytes,
                  std::span<uint8_t, kSessionHashSize> output)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_MD5_ALGORITHM, nullptr, 0)))
    {
        return false;
    }

    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS           status =
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    if (BCRYPT_SUCCESS(status))
    {
        status = BCryptHashData(hash, const_cast<uint8_t*>(bytes.data()), static_cast<ULONG>(bytes.size()), 0);
    }
    if (BCRYPT_SUCCESS(status))
    {
        status = BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0);
    }

    if (hash != nullptr)
    {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return BCRYPT_SUCCESS(status);
}

} // namespace

bool PrepareLobbySend(std::span<const uint8_t> source, uint16_t peer_port, uint16_t data_port, uint16_t view_port, const SessionHash& session_hash, const ClientVersion& client_version, std::vector<uint8_t>& output)
{
    output.clear();
    if ((peer_port != data_port && peer_port != view_port) ||
        source.size() < kDataRequestSize ||
        !std::equal(kLobbyMarker.begin(), kLobbyMarker.end(), source.begin() + 4))
    {
        return false;
    }

    const uint32_t command = ReadLe32(source, 8);
    if (std::find(kAuthenticatedLobbyCommands.begin(),
                  kAuthenticatedLobbyCommands.end(),
                  command) == kAuthenticatedLobbyCommands.end())
    {
        return false;
    }

    output.assign(source.begin(), source.end());
    CopySessionHash(output, session_hash);
    if (command == 0x26)
    {
        if (peer_port != view_port || output.size() < kViewLoginSize)
        {
            output.clear();
            return false;
        }
        std::copy(client_version.begin(), client_version.end(), output.begin() + 116);
    }
    return true;
}

std::expected<LobbyIdentifier, ParseError>
CalculateLobbyIdentifier(std::span<const uint8_t> bytes)
{
    if (bytes.size() < kLobbyHeaderSize)
    {
        return std::unexpected(ParseError::kTruncated);
    }

    const uint32_t packet_size = ReadLe32(bytes, 0);
    if (packet_size < kLobbyHeaderSize || packet_size > bytes.size())
    {
        return std::unexpected(ParseError::kInvalidSize);
    }

    std::vector<uint8_t> hash_input(bytes.begin(), bytes.begin() + packet_size);
    std::fill(hash_input.begin() + 12, hash_input.begin() + 28, uint8_t{ 0 });

    LobbyIdentifier identifier{};
    if (!CalculateMd5(hash_input, identifier))
    {
        return std::unexpected(ParseError::kChecksumUnavailable);
    }
    return identifier;
}

std::array<uint8_t, kDataRequestSize>
MakeDataBind(const SessionHash& session_hash)
{
    std::array<uint8_t, kDataRequestSize> packet{};
    packet[0] = 0xFE;
    CopySessionHash(packet, session_hash);
    return packet;
}

std::array<uint8_t, kDataRequestSize>
MakeDataAccountRequest(const SessionMaterial& session,
                       const Ipv4Address&     server_address)
{
    std::array<uint8_t, kDataRequestSize> packet{};
    packet[0] = 0xA1;
    WriteLe32(packet, 1, session.account_id);
    std::copy(server_address.begin(), server_address.end(), packet.begin() + 5);
    CopySessionHash(packet, session.session_hash);
    return packet;
}

std::array<uint8_t, kDataRequestSize>
MakeDataSelectionRequest(const MapSessionKey& map_session_key)
{
    std::array<uint8_t, kDataRequestSize> packet{};
    packet[0] = 0xA2;
    std::copy(map_session_key.begin(), map_session_key.end(), packet.begin() + 1);
    return packet;
}

bool GenerateMapSessionKey(MapSessionKey& map_session_key)
{
    map_session_key.fill(0);
    const NTSTATUS status = BCryptGenRandom(
        nullptr, map_session_key.data(), static_cast<ULONG>(map_session_key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
    {
        map_session_key.fill(0);
        return false;
    }
    return true;
}

void AdvanceMapSessionKey(MapSessionKey& map_session_key)
{
    constexpr size_t kRolloverWordOffset = 4 * sizeof(uint32_t);
    const uint32_t   rollover_word =
        ReadLe32(map_session_key, kRolloverWordOffset);
    WriteLe32(map_session_key, kRolloverWordOffset, rollover_word + 2);
}

bool DeriveMapCipherKey(const MapSessionKey& map_session_key,
                        MapCipherKey&        map_cipher_key)
{
    map_cipher_key.fill(0);
    if (!CalculateMd5(map_session_key, map_cipher_key))
    {
        map_cipher_key.fill(0);
        return false;
    }
    const auto first_zero =
        std::find(map_cipher_key.begin(), map_cipher_key.end(), uint8_t{ 0 });
    std::fill(first_zero, map_cipher_key.end(), uint8_t{ 0 });
    return true;
}

std::array<uint8_t, kViewLoginSize>
MakeViewLogin(const SessionHash&   session_hash,
              const ClientVersion& client_version)
{
    std::array<uint8_t, kViewLoginSize> packet{};
    WriteLe32(packet, 0, kViewLoginSize);
    WriteLe32(packet, 4, kLobbyTerminator);
    WriteLe32(packet, 8, 0x26);
    CopySessionHash(packet, session_hash);
    std::copy(client_version.begin(), client_version.end(), packet.begin() + 116);
    return packet;
}

std::expected<KeyResponse, ParseError>
ParseKeyResponse(std::span<const uint8_t> bytes)
{
    auto packet_size = ValidateLobbyHeader(bytes, 0x05, kKeyResponseSize);
    if (!packet_size)
    {
        return std::unexpected(packet_size.error());
    }
    if (*packet_size != kKeyResponseSize)
    {
        return std::unexpected(ParseError::kInvalidSize);
    }
    if (auto identifier = ValidateLobbyIdentifier(bytes, *packet_size);
        !identifier)
    {
        return std::unexpected(identifier.error());
    }

    return KeyResponse{
        .key            = ReadLe32(bytes, 28),
        .expansion_mask = ReadLe32(bytes, 32),
        .feature_mask   = ReadLe32(bytes, 36),
    };
}

bool IsCompleteKeyResponse(std::span<const uint8_t> bytes)
{
    return bytes.size() == kKeyResponseSize && ParseKeyResponse(bytes).has_value();
}

std::expected<CharacterList, ParseError>
ParseCharacterList(std::span<const uint8_t> bytes)
{
    auto packet_size = ValidateLobbyHeader(bytes, 0x20, kCharacterListHeaderSize);
    if (!packet_size)
    {
        return std::unexpected(packet_size.error());
    }

    const uint32_t character_count = ReadLe32(bytes, 28);
    if (character_count > 16)
    {
        return std::unexpected(ParseError::kInvalidCharacterCount);
    }
    const size_t expected_size =
        kCharacterListHeaderSize + kCharacterEntrySize * character_count;
    if (*packet_size != expected_size)
    {
        return std::unexpected(ParseError::kInvalidSize);
    }
    if (auto identifier = ValidateLobbyIdentifier(bytes, *packet_size);
        !identifier)
    {
        return std::unexpected(identifier.error());
    }

    CharacterList result;
    result.characters.reserve(character_count);
    for (uint32_t i = 0; i < character_count; ++i)
    {
        const size_t entry_offset =
            kCharacterListHeaderSize + i * kCharacterEntrySize;
        const size_t name_offset = entry_offset + 12;
        const auto   name_end =
            std::find(bytes.begin() + name_offset, bytes.begin() + name_offset + 16, uint8_t{ 0 });
        result.characters.push_back(CharacterSummary{
            .content_id = ReadLe32(bytes, entry_offset),
            .status     = ReadLe16(bytes, entry_offset + 8),
            .name       = std::string(bytes.begin() + name_offset, name_end),
        });
    }
    return result;
}

} // namespace revana::login
