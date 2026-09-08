#include <login/lobby_packets.h>

#include "check.h"
#include <algorithm>

namespace
{

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
    CHECK(identifier);
    std::copy(identifier->begin(), identifier->end(), bytes.begin() + 12);
}

} // namespace

int main()
{
    using namespace revana::login;

    SessionHash session_hash{};
    for (uint8_t i = 0; i < session_hash.size(); ++i)
    {
        session_hash[i] = i;
    }
    const SessionMaterial session{
        .account_id   = 0x78563412,
        .session_hash = session_hash,
    };

    const auto bind = MakeDataBind(session_hash);
    CHECK(bind[0] == 0xFE);
    CHECK(
        std::equal(session_hash.begin(), session_hash.end(), bind.begin() + 12));

    const auto account_request =
        MakeDataAccountRequest(session, Ipv4Address{ 127, 0, 0, 1 });
    CHECK(account_request[0] == 0xA1);
    CHECK(account_request[1] == 0x12);
    CHECK(account_request[4] == 0x78);
    CHECK(account_request[5] == 127);
    CHECK(account_request[8] == 1);
    CHECK(std::equal(session_hash.begin(), session_hash.end(), account_request.begin() + 12));

    MapSessionKey map_session_key{};
    for (uint8_t i = 0; i < map_session_key.size(); ++i)
    {
        map_session_key[i] = static_cast<uint8_t>(0x40 + i);
    }
    const auto selection_request = MakeDataSelectionRequest(map_session_key);
    CHECK(selection_request[0] == 0xA2);
    CHECK(std::equal(map_session_key.begin(), map_session_key.end(), selection_request.begin() + 1));
    CHECK(std::all_of(selection_request.begin() + 21,
                      selection_request.end(),
                      [](uint8_t byte)
                      {
                          return byte == 0;
                      }));

    MapCipherKey map_cipher_key{};
    CHECK(DeriveMapCipherKey(map_session_key, map_cipher_key));
    constexpr MapCipherKey kExpectedMapCipherKey{
        0x6B,
        0x7E,
        0x62,
        0xB6,
        0x2D,
        0xF0,
        0xC7,
        0x69,
        0xCA,
        0xC4,
        0x86,
        0xE1,
        0xCE,
        0x52,
        0x8C,
        0xAB,
    };
    CHECK(map_cipher_key == kExpectedMapCipherKey);

    constexpr MapSessionKey kZeroDigestMapSessionKey{
        0x1A,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
    };
    constexpr MapCipherKey kExpectedZeroDigestMapCipherKey{
        0xD8,
        0x58,
        0xB4,
        0x76,
        0xDE,
        0xEC,
        0x14,
        0x62,
        0xBA,
        0x4F,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };
    CHECK(DeriveMapCipherKey(kZeroDigestMapSessionKey, map_cipher_key));
    CHECK(map_cipher_key == kExpectedZeroDigestMapCipherKey);

    MapSessionKey generated_key{};
    CHECK(GenerateMapSessionKey(generated_key));
    CHECK(std::any_of(generated_key.begin(), generated_key.end(), [](uint8_t byte)
                      {
                          return byte != 0;
                      }));

    MapSessionKey advanced_key{};
    advanced_key[16] = 0xFE;
    AdvanceMapSessionKey(advanced_key);
    CHECK(advanced_key[4] == 0x00);
    CHECK(advanced_key[16] == 0x00);
    CHECK(advanced_key[17] == 0x01);

    ClientVersion client_version{ '3', '0', '1', '8', '1', '2', '0', '5', '_', '0' };
    const auto    view_login = MakeViewLogin(session_hash, client_version);
    CHECK(view_login[0] == kViewLoginSize);
    CHECK(view_login[4] == 0x49);
    CHECK(view_login[8] == 0x26);
    CHECK(std::equal(client_version.begin(), client_version.end(), view_login.begin() + 116));

    std::vector<uint8_t> guest_packet(kViewCharacterRequestSize);
    WriteLe32(guest_packet, 0, kViewCharacterRequestSize);
    WriteLe32(guest_packet, 4, kLobbyTerminator);
    WriteLe32(guest_packet, 8, 0x1F);
    const auto           original_guest_packet = guest_packet;
    std::vector<uint8_t> prepared;
    CHECK(PrepareLobbySend(guest_packet, 54001, 54230, 54001, session_hash, client_version, prepared));
    CHECK(guest_packet == original_guest_packet);
    CHECK(std::equal(session_hash.begin(), session_hash.end(), prepared.begin() + 12));

    prepared.clear();
    CHECK(!PrepareLobbySend(guest_packet, 1, 54230, 54001, session_hash, client_version, prepared));
    CHECK(prepared.empty());

    auto                    guest_view_login = view_login;
    constexpr ClientVersion retail_version{ '4', '0', '0', '6', '0', '4', 'x', 'x', '_', 'x' };
    std::copy(retail_version.begin(), retail_version.end(), guest_view_login.begin() + 116);
    const auto original_guest_view_login = guest_view_login;
    CHECK(PrepareLobbySend(guest_view_login, 54001, 54230, 54001, session_hash, client_version, prepared));
    CHECK(guest_view_login == original_guest_view_login);
    CHECK(std::equal(client_version.begin(), client_version.end(), prepared.begin() + 116));

    std::array<uint8_t, kKeyResponseSize> key_packet{};
    WriteLe32(key_packet, 0, kKeyResponseSize);
    WriteLe32(key_packet, 4, kLobbyTerminator);
    WriteLe32(key_packet, 8, 0x05);
    WriteLe32(key_packet, 28, 0xAD5DE04F);
    WriteLe32(key_packet, 32, 0x11223344);
    WriteLe32(key_packet, 36, 0x55667788);
    ApplyIdentifier(key_packet);
    constexpr LobbyIdentifier kExpectedKeyIdentifier{
        0x65,
        0x9F,
        0x32,
        0x5F,
        0xC4,
        0x20,
        0x67,
        0x2E,
        0x63,
        0x17,
        0x32,
        0x68,
        0x08,
        0xD0,
        0x7E,
        0x37,
    };
    CHECK(std::equal(kExpectedKeyIdentifier.begin(),
                     kExpectedKeyIdentifier.end(),
                     key_packet.begin() + 12));
    const auto key = ParseKeyResponse(key_packet);
    CHECK(key);
    CHECK(key->key == 0xAD5DE04F);
    CHECK(key->expansion_mask == 0x11223344);
    CHECK(key->feature_mask == 0x55667788);
    CHECK(IsCompleteKeyResponse(key_packet));
    CHECK(!IsCompleteKeyResponse(std::span<const uint8_t>(
        key_packet.data(), key_packet.size() - 1)));
    key_packet[12] ^= 1;
    CHECK(!IsCompleteKeyResponse(key_packet));
    key_packet[12] ^= 1;

    std::array<uint8_t, 0xAC> character_packet{};
    WriteLe32(character_packet, 0, character_packet.size());
    WriteLe32(character_packet, 4, kLobbyTerminator);
    WriteLe32(character_packet, 8, 0x20);
    WriteLe32(character_packet, 28, 1);
    WriteLe32(character_packet, 32, 0x00123456);
    character_packet[40]            = 1;
    constexpr char kCharacterName[] = "Testchar";
    std::copy_n(kCharacterName, sizeof(kCharacterName), character_packet.begin() + 44);
    ApplyIdentifier(character_packet);

    const auto characters = ParseCharacterList(character_packet);
    CHECK(characters);
    CHECK(characters->characters.size() == 1);
    CHECK(characters->characters[0].content_id == 0x00123456);
    CHECK(characters->characters[0].status == 1);
    CHECK(characters->characters[0].name == "Testchar");

    character_packet[44] ^= 1;
    const auto tampered = ParseCharacterList(character_packet);
    CHECK(!tampered);
    CHECK(tampered.error() == ParseError::kInvalidIdentifier);
    character_packet[44] ^= 1;

    character_packet[28]     = 17;
    const auto invalid_count = ParseCharacterList(character_packet);
    CHECK(!invalid_count);
    CHECK(invalid_count.error() == ParseError::kInvalidCharacterCount);
}
