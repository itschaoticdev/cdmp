#include "common/relay.h"

#include <algorithm>
#include <cstring>

namespace cdmp::net::relay {

namespace {

constexpr uint8_t kMagic[3] = {'C', 'D', 'R'};

}  // namespace

const char* status_text(Status s) {
    switch (s) {
        case Status::Ok: return "ok";
        case Status::RoomTaken: return "someone else is hosting this room";
        case Status::NoHost: return "nobody is hosting this room yet";
        case Status::RoomFull: return "the room is full";
        case Status::Busy: return "the relay is full, try again later";
    }
    return "unknown";
}

std::optional<Frame> decode(std::span<const uint8_t> bytes) {
    if (bytes.size() < kHeader || bytes.size() > kHeader + kMaxPayload) return std::nullopt;
    if (std::memcmp(bytes.data(), kMagic, 3) != 0 || bytes[3] != kVersion) return std::nullopt;
    Frame f;
    f.type = static_cast<Type>(bytes[4]);
    std::memcpy(f.room.data(), bytes.data() + 5, f.room.size());
    f.body = bytes.subspan(kHeader);
    return f;
}

std::vector<uint8_t> encode(Type type, const RoomId& room, std::span<const uint8_t> body) {
    std::vector<uint8_t> out(kHeader + body.size());
    std::memcpy(out.data(), kMagic, 3);
    out[3] = kVersion;
    out[4] = static_cast<uint8_t>(type);
    std::memcpy(out.data() + 5, room.data(), room.size());
    if (!body.empty()) std::memcpy(out.data() + kHeader, body.data(), body.size());
    return out;
}

std::vector<uint8_t> encode_join(const RoomId& room, Role role) {
    std::vector<uint8_t> body(kJoinSize - kHeader, 0);
    body[0] = static_cast<uint8_t>(role);
    return encode(Type::Join, room, body);
}

uint64_t RelayCore::key_of(const RoomId& id) {
    uint64_t k;
    std::memcpy(&k, id.data(), sizeof k);
    return k;
}

uint64_t RelayCore::key_of(const Endpoint& ep) {
    return (static_cast<uint64_t>(ep.ip) << 16) | ep.port;
}

bool RelayCore::allow(const Endpoint& from, uint32_t now_ms) {
    // Bounded: a flood from many spoofed sources must not grow this forever.
    if (buckets_.size() > 4 * kMaxRooms) {
        std::erase_if(buckets_, [&](const auto& kv) { return now_ms - kv.second.last_ms > 10000; });
        if (buckets_.size() > 4 * kMaxRooms) buckets_.clear();
    }
    Bucket& b = buckets_[key_of(from)];
    if (b.last_ms != 0) {
        b.tokens = std::min(kBurst, b.tokens + (now_ms - b.last_ms) * kPacketsPerSecond / 1000.0);
    }
    b.last_ms = now_ms ? now_ms : 1;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
}

void RelayCore::on_datagram(const Endpoint& from, std::span<const uint8_t> bytes, uint32_t now_ms,
                            std::vector<Out>& out) {
    auto frame = decode(bytes);
    if (!frame) {
        ++stats_.dropped;
        return;
    }
    if (!allow(from, now_ms)) {
        ++stats_.rate_limited;
        return;
    }
    switch (frame->type) {
        case Type::Join:
            if (bytes.size() < kJoinSize || (frame->body[0] != 1 && frame->body[0] != 2)) {
                ++stats_.dropped;
                return;
            }
            join(from, frame->room, static_cast<Role>(frame->body[0]), now_ms, out);
            return;
        case Type::Leave:
            leave(from, out);
            return;
        case Type::Data: {
            auto r = room_of_.find(key_of(from));
            if (r == room_of_.end() || r->second != key_of(frame->room)) {
                ++stats_.dropped;  // not in this room: never answered, never forwarded
                return;
            }
            Room& room = rooms_.at(r->second);
            const bool from_host = room.host.used && room.host.ep == from;
            Slot& self = from_host ? room.host : room.guest;
            Slot& other = from_host ? room.guest : room.host;
            self.last_ms = now_ms;
            if (!other.used) {
                ++stats_.dropped;
                return;
            }
            out.push_back({other.ep, encode(Type::Forward, room.id, frame->body)});
            ++stats_.forwarded;
            return;
        }
        default:
            ++stats_.dropped;
            return;
    }
}

void RelayCore::join(const Endpoint& from, const RoomId& id, Role role, uint32_t now_ms,
                     std::vector<Out>& out) {
    auto reply = [&](Status st, bool peer) {
        const uint8_t body[2] = {static_cast<uint8_t>(st), static_cast<uint8_t>(peer)};
        out.push_back({from, encode(Type::JoinAck, id, body)});
    };
    const uint64_t key = key_of(id);

    // One room per endpoint: joining another leaves the old one.
    if (auto r = room_of_.find(key_of(from)); r != room_of_.end() && r->second != key) leave(from, out);

    auto it = rooms_.find(key);
    if (it == rooms_.end()) {
        if (role == Role::Guest) {
            reply(Status::NoHost, false);
            return;
        }
        if (rooms_.size() >= kMaxRooms) {
            reply(Status::Busy, false);
            return;
        }
        it = rooms_.emplace(key, Room{id, {}, {}}).first;
    }
    Room& room = it->second;
    Slot& self = role == Role::Host ? room.host : room.guest;
    Slot& other = role == Role::Host ? room.guest : room.host;

    if (role == Role::Guest && !room.host.used) {
        reply(Status::NoHost, false);
        return;
    }
    if (self.used && !(self.ep == from) && now_ms - self.last_ms < kSlotTimeoutMs) {
        reply(role == Role::Host ? Status::RoomTaken : Status::RoomFull, other.used);
        return;
    }
    const bool is_new = !self.used || !(self.ep == from);
    if (self.used && !(self.ep == from)) room_of_.erase(key_of(self.ep));
    self.ep = from;
    self.used = true;
    self.last_ms = now_ms;
    room_of_[key_of(from)] = key;
    reply(Status::Ok, other.used);
    if (is_new && other.used) {
        const uint8_t present = 1;
        out.push_back({other.ep, encode(Type::Peer, id, {&present, 1})});
    }
}

void RelayCore::free_slot(Room& room, bool host_slot, std::vector<Out>& out) {
    Slot& self = host_slot ? room.host : room.guest;
    Slot& other = host_slot ? room.guest : room.host;
    room_of_.erase(key_of(self.ep));
    self = Slot{};
    if (other.used) {
        const uint8_t present = 0;
        out.push_back({other.ep, encode(Type::Peer, room.id, {&present, 1})});
    }
}

void RelayCore::leave(const Endpoint& from, std::vector<Out>& out) {
    auto r = room_of_.find(key_of(from));
    if (r == room_of_.end()) return;
    const uint64_t key = r->second;
    Room& room = rooms_.at(key);
    free_slot(room, room.host.used && room.host.ep == from, out);
    if (!room.host.used && !room.guest.used) rooms_.erase(key);
}

void RelayCore::expire(uint32_t now_ms, std::vector<Out>& out) {
    for (auto it = rooms_.begin(); it != rooms_.end();) {
        Room& room = it->second;
        if (room.host.used && now_ms - room.host.last_ms >= kSlotTimeoutMs) free_slot(room, true, out);
        if (room.guest.used && now_ms - room.guest.last_ms >= kSlotTimeoutMs) free_slot(room, false, out);
        it = (!room.host.used && !room.guest.used) ? rooms_.erase(it) : std::next(it);
    }
}

}  // namespace cdmp::net::relay
