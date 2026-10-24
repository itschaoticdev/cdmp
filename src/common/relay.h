#pragma once
// Relay for players who are not Steam friends. Both players send to the
// relay and it forwards between the two endpoints of a room, so neither sees
// the other's IP. The relay only knows a room id (a hash of the room code);
// what it forwards is sealed with RoomCipher and opaque to it.
//
// Every datagram: 'C' 'D' 'R' version | type | room id (8) | body.
// RelayCore is the socket-free logic of the server (tools/relay), so the
// tests can drive it directly.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "common/room_code.h"
#include "common/udp.h"

namespace cdmp::net::relay {

inline constexpr uint8_t kVersion = 1;
inline constexpr size_t kHeader = 4 + 1 + 8;
// A Join is padded to this size and the relay answers with less, so the
// relay cannot be used to amplify traffic toward a spoofed address.
inline constexpr size_t kJoinSize = 64;
inline constexpr size_t kMaxPayload = 1400;

enum class Type : uint8_t {
    Join = 1,     // body: role (1 = host, 2 = guest), then padding
    Data = 2,     // body: sealed bytes, forwarded to the other player
    Leave = 3,
    JoinAck = 0x81,  // body: status, peer present (0/1)
    Peer = 0x82,     // body: peer present (0/1)
    Forward = 0x83,  // body: sealed bytes from the other player
};

enum class Role : uint8_t { Host = 1, Guest = 2 };

enum class Status : uint8_t {
    Ok = 0,
    RoomTaken = 1,  // another host holds this room
    NoHost = 2,     // nobody is hosting this room (yet)
    RoomFull = 3,   // another guest is already in
    Busy = 4,       // the relay has no room left
};
const char* status_text(Status s);

struct Frame {
    Type type{};
    RoomId room{};
    std::span<const uint8_t> body;
};

std::optional<Frame> decode(std::span<const uint8_t> bytes);
std::vector<uint8_t> encode(Type type, const RoomId& room, std::span<const uint8_t> body = {});
std::vector<uint8_t> encode_join(const RoomId& room, Role role);

class RelayCore {
public:
    struct Out {
        Endpoint to;
        std::vector<uint8_t> bytes;
    };
    struct Stats {
        uint64_t forwarded = 0;
        uint64_t dropped = 0;
        uint64_t rate_limited = 0;
    };

    static constexpr uint32_t kSlotTimeoutMs = 15000;
    static constexpr size_t kMaxRooms = 4096;
    static constexpr int kMaxHostedPerIp = 8;  // one address cannot take every room
    static constexpr double kPacketsPerSecond = 400;  // ~20 Hz state + reliable bursts
    static constexpr double kBurst = 800;             // a Spawn is up to ~220 fragments at once

    void on_datagram(const Endpoint& from, std::span<const uint8_t> bytes, uint32_t now_ms,
                     std::vector<Out>& out);
    // Frees slots that went quiet and tells the other player.
    void expire(uint32_t now_ms, std::vector<Out>& out);

    size_t rooms() const { return rooms_.size(); }
    const Stats& stats() const { return stats_; }

private:
    struct Slot {
        Endpoint ep;
        uint32_t last_ms = 0;
        bool used = false;
    };
    struct Room {
        RoomId id{};
        Slot host;
        Slot guest;
    };
    struct Bucket {
        double tokens = kBurst;
        uint32_t last_ms = 0;
    };

    static uint64_t key_of(const RoomId& id);
    static uint64_t key_of(const Endpoint& ep);
    bool allow(const Endpoint& from, uint32_t now_ms);
    void join(const Endpoint& from, const RoomId& id, Role role, uint32_t now_ms, std::vector<Out>& out);
    void leave(const Endpoint& from, std::vector<Out>& out);
    void free_slot(Room& room, bool host_slot, std::vector<Out>& out);
    void set_slot(Room& room, bool host_slot, const Endpoint& ep, uint32_t now_ms);

    std::unordered_map<uint64_t, Room> rooms_;
    std::unordered_map<uint64_t, uint64_t> room_of_;  // endpoint -> room
    std::unordered_map<uint64_t, Bucket> buckets_;
    std::unordered_map<uint32_t, int> hosted_per_ip_;
    Stats stats_;
};

}  // namespace cdmp::net::relay
