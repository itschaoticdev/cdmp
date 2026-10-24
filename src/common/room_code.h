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

// AES-256-GCM between the two players. The room key alone is never used to
// encrypt: the counter restarts with every launch and a code can be used
// twice, which with one key would repeat GCM nonces (plaintext leak and
// forgeries). So each side picks a random 64-bit session at init and seals
// with SHA-256(label + room key + direction + session); the session and the
// counter travel in clear and a sliding window rejects replays. A peer
// that restarts shows up with a new session; sessions already left behind
// are refused, so old traffic cannot drag us back.
class RoomCipher {
public:
    enum class Direction : uint8_t { HostToGuest = 1, GuestToHost = 2 };
    static constexpr size_t kOverhead = 8 + 8 + 16;  // session + counter + tag

    RoomCipher() = default;
    ~RoomCipher();
    RoomCipher(const RoomCipher&) = delete;
    RoomCipher& operator=(const RoomCipher&) = delete;

    bool init(const RoomSecrets& secrets, Direction mine);
    bool ready() const { return key_ != nullptr; }
    uint64_t session() const { return send_session_; }

    // Appends counter | ciphertext | tag to out.
    bool seal(std::span<const uint8_t> plain, std::vector<uint8_t>& out);
    // The plaintext size written to plain_out, or nullopt if it is forged,
    // replayed, too old or does not fit.
    std::optional<size_t> open(std::span<const uint8_t> sealed, std::span<uint8_t> plain_out);

private:
    struct Window {
        uint64_t highest = 0;
        uint64_t bits = 0;  // bit i = counter (highest - i) seen
    };
    static bool accept_counter(Window& w, uint64_t counter);
    void* make_key(Direction dir, uint64_t session) const;  // BCRYPT_KEY_HANDLE or null

    RoomKeyBytes room_key_{};
    RoomId room_id_{};
    Direction mine_ = Direction::HostToGuest;
    void* key_ = nullptr;  // ours: sealing
    uint64_t send_session_ = 0;
    uint64_t send_counter_ = 0;
    void* peer_key_ = nullptr;  // the other side's current session: opening
    uint64_t peer_session_ = 0;
    Window window_;
    std::array<uint64_t, 8> old_sessions_{};  // peer sessions we moved away from
    size_t old_next_ = 0;
};

}  // namespace cdmp::net
