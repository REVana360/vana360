#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace revana::login
{

inline constexpr size_t   kSessionHashSize          = 16;
inline constexpr size_t   kMapSessionKeySize        = 20;
inline constexpr size_t   kClientVersionSize        = 10;
inline constexpr size_t   kDataRequestSize          = 28;
inline constexpr size_t   kViewLoginSize            = 152;
inline constexpr size_t   kViewCharacterRequestSize = 44;
inline constexpr size_t   kKeyResponseSize          = 40;
inline constexpr size_t   kLobbyHeaderSize          = 28;
inline constexpr size_t   kCharacterListHeaderSize  = 32;
inline constexpr size_t   kCharacterEntrySize       = 140;
inline constexpr uint32_t kLobbyTerminator          = 0x46465849;

using SessionHash     = std::array<uint8_t, kSessionHashSize>;
using MapSessionKey   = std::array<uint8_t, kMapSessionKeySize>;
using MapCipherKey    = std::array<uint8_t, kSessionHashSize>;
using LobbyIdentifier = std::array<uint8_t, kSessionHashSize>;
using ClientVersion   = std::array<uint8_t, kClientVersionSize>;
using Ipv4Address     = std::array<uint8_t, 4>;

struct SessionMaterial
{
    uint32_t    account_id = 0;
    SessionHash session_hash{};
};

std::array<uint8_t, kDataRequestSize>
MakeDataBind(const SessionHash& session_hash);

std::array<uint8_t, kDataRequestSize>
MakeDataAccountRequest(const SessionMaterial& session,
                       const Ipv4Address&     server_address,
                       bool                   include_session_hash);

std::array<uint8_t, kDataRequestSize>
MakeDataSelectionRequest(const MapSessionKey& map_session_key);

// Generates the key shared by the client and map server after character
// selection. The caller owns and must clear the returned key material.
bool GenerateMapSessionKey(MapSessionKey& map_session_key);

// LandSandBoat derives the map Blowfish key by hashing the 20-byte selection
// key, then zeroing the digest from its first zero byte onward. The Xbox client
// consumes this 16-byte key during its map handoff.
bool DeriveMapCipherKey(const MapSessionKey& map_session_key,
                        MapCipherKey&        map_cipher_key);

std::array<uint8_t, kViewLoginSize>
MakeViewLogin(const SessionHash&   session_hash,
              const ClientVersion& client_version);

std::array<uint8_t, kViewCharacterRequestSize>
MakeViewCharacterRequest(const SessionHash& session_hash);

// Copies and authenticates a recognized lobby packet for transmission without
// modifying the guest-owned source buffer. Returns false for unrelated traffic.
bool PrepareLobbySend(std::span<const uint8_t> source, uint16_t peer_port, uint16_t data_port, uint16_t view_port, const SessionHash& session_hash, const ClientVersion& client_version, std::vector<uint8_t>& output);

enum class ParseError
{
    kTruncated,
    kInvalidSize,
    kInvalidTerminator,
    kUnexpectedCommand,
    kInvalidCharacterCount,
    kInvalidIdentifier,
    kChecksumUnavailable,
};

std::expected<LobbyIdentifier, ParseError>
CalculateLobbyIdentifier(std::span<const uint8_t> bytes);

struct KeyResponse
{
    uint32_t key            = 0;
    uint32_t expansion_mask = 0;
    uint32_t feature_mask   = 0;
};

std::expected<KeyResponse, ParseError>
ParseKeyResponse(std::span<const uint8_t> bytes);

struct CharacterSummary
{
    uint32_t    content_id = 0;
    uint16_t    status     = 0;
    std::string name;
};

struct CharacterList
{
    std::vector<CharacterSummary> characters;
};

std::expected<CharacterList, ParseError>
ParseCharacterList(std::span<const uint8_t> bytes);

} // namespace revana::login
