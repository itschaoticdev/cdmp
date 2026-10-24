#pragma once
// Room codes for the relay transport. The code is the only secret: it names
// the room on the relay (a hash the relay sees) and keys the encryption
// between the two players (which the relay never sees). 16 Crockford base32
// characters = 80 random bits, written XXXX-XXXX-XXXX-XXXX.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cdmp::net {

inline constexpr size_t kRoomCodeChars = 16;
using RoomId = std::array<uint8_t, 8>;
using RoomKeyBytes = std::array<uint8_t, 32>;

// A fresh random code, canonical (16 characters, no dashes).
std::string generate_room_code();
// Accepts what a person types: any case, spaces or dashes, and O/I/L for
// 0/1/1. The canonical 16 characters, or nullopt if it is not a code.
std::optional<std::string> normalize_room_code(std::string_view text);
// XXXX-XXXX-XXXX-XXXX, for showing and sharing.
std::string format_room_code(const std::string& canonical);

struct RoomSecrets {
    RoomId room_id{};      // SHA-256("cdmp-room-v1" + code), first 8 bytes
    RoomKeyBytes key{};    // SHA-256("cdmp-key-v1" + code)
};
RoomSecrets derive_room_secrets(const std::string& canonical);

// AES-256-GCM between the two players. Each side seals with its own
// direction and opens the other's; the nonce is direction + a counter that
// travels in clear, and a sliding window rejects replays.
class RoomCipher {
public:
    enum class Direction : uint8_t { HostToGuest = 1, GuestToHost = 2 };
    static constexpr size_t kOverhead = 8 + 16;  // counter + tag

    RoomCipher() = default;
    ~RoomCipher();
    RoomCipher(const RoomCipher&) = delete;
    RoomCipher& operator=(const RoomCipher&) = delete;

    bool init(const RoomSecrets& secrets, Direction mine);
    bool ready() const { return key_ != nullptr; }

    // Appends counter | ciphertext | tag to out.
    bool seal(std::span<const uint8_t> plain, std::vector<uint8_t>& out);
    // The plaintext size written to plain_out, or nullopt if it is forged,
    // replayed, too old or does not fit.
    std::optional<size_t> open(std::span<const uint8_t> sealed, std::span<uint8_t> plain_out);

private:
    bool accept_counter(uint64_t counter);

    void* key_ = nullptr;  // BCRYPT_KEY_HANDLE
    RoomId room_id_{};
    Direction mine_ = Direction::HostToGuest;
    uint64_t send_counter_ = 0;
    uint64_t recv_highest_ = 0;
    uint64_t recv_window_ = 0;  // bit i = counter (recv_highest_ - i) seen
};

}  // namespace cdmp::net
