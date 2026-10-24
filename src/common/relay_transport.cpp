#include "common/relay_transport.h"

#include "common/clock.h"

namespace cdmp::net {

namespace {

constexpr uint32_t kJoinEveryMs = 2000;      // keeps the slot and the NAT mapping alive
constexpr uint32_t kJoinRetryMs = 500;       // until the relay answers
constexpr uint32_t kRelaySilentMs = 10000;   // no answer for this long = not joined any more

}  // namespace

bool RelayTransport::open(const Endpoint& relay, const std::string& code, bool host) {
    if (!sock_.open(0, /*loopback_only=*/relay.is_loopback())) return false;
    relay_ = relay;
    code_ = code;
    host_ = host;
    secrets_ = derive_room_secrets(code);
    if (!cipher_.init(secrets_, host ? RoomCipher::Direction::HostToGuest : RoomCipher::Direction::GuestToHost)) {
        return false;
    }
    scratch_.reserve(relay::kHeader + relay::kMaxPayload);
    return true;
}

bool RelayTransport::send(const PeerAddr& to, std::span<const uint8_t> data) {
    if (to.kind != PeerAddr::Kind::Relay || !joined_ || !peer_present_) return false;
    if (data.size() + RoomCipher::kOverhead > relay::kMaxPayload) return false;
    scratch_.clear();
    if (!cipher_.seal(data, scratch_)) return false;
    return sock_.send_to(relay_, relay::encode(relay::Type::Data, secrets_.room_id, scratch_));
}

bool RelayTransport::handle(std::span<const uint8_t> bytes, std::span<uint8_t> buf, size_t& n) {
    auto frame = relay::decode(bytes);
    if (!frame || frame->room != secrets_.room_id) return false;
    last_heard_ms_ = now_ms_;
    switch (frame->type) {
        case relay::Type::JoinAck:
            if (frame->body.size() < 2) return false;
            last_status_ = static_cast<relay::Status>(frame->body[0]);
            joined_ = last_status_ == relay::Status::Ok;
            peer_present_ = joined_ && frame->body[1] != 0;
            return false;
        case relay::Type::Peer:
            if (frame->body.empty()) return false;
            peer_present_ = frame->body[0] != 0;
            return false;
        case relay::Type::Forward:
            if (auto len = cipher_.open(frame->body, buf)) {
                n = *len;
                return true;
            }
            return false;  // not from the other player, or replayed
        default:
            return false;
    }
}

std::optional<size_t> RelayTransport::recv(PeerAddr& from, std::span<uint8_t> buf, int timeout_ms) {
    uint8_t raw[relay::kHeader + relay::kMaxPayload];
    // Control frames (acks, peer events) are handled here and never returned,
    // so keep reading until data arrives or the time is up.
    const uint32_t deadline = cdmp::now_ms() + static_cast<uint32_t>(timeout_ms);
    for (;;) {
        const int32_t left = static_cast<int32_t>(deadline - cdmp::now_ms());
        Endpoint ep;
        auto got = sock_.recv_from(ep, raw, left > 0 ? left : 0);
        if (!got) return std::nullopt;
        size_t n = 0;
        if (ep == relay_ && handle({raw, *got}, buf, n)) {
            from = PeerAddr::relay();
            return n;
        }
    }
}

void RelayTransport::poll(uint32_t now_ms) {
    now_ms_ = now_ms;
    if (joined_ && last_heard_ms_ && now_ms - last_heard_ms_ > kRelaySilentMs) {
        joined_ = false;
        peer_present_ = false;
    }
    const uint32_t every = joined_ ? kJoinEveryMs : kJoinRetryMs;
    if (last_join_ms_ == 0 || now_ms - last_join_ms_ >= every) {
        last_join_ms_ = now_ms ? now_ms : 1;
        sock_.send_to(relay_, relay::encode_join(secrets_.room_id, host_ ? relay::Role::Host : relay::Role::Guest));
    }
}

void RelayTransport::leave() {
    if (joined_) sock_.send_to(relay_, relay::encode(relay::Type::Leave, secrets_.room_id));
    joined_ = false;
    peer_present_ = false;
}

std::string RelayTransport::status() const {
    std::string s = "relay " + relay_.str() + " room " + format_room_code(code_);
    if (!joined_) {
        s += last_status_ == relay::Status::Ok ? " (reaching the relay)"
                                               : std::string(" (") + relay::status_text(last_status_) + ")";
    } else {
        s += peer_present_ ? " (other player in the room)" : " (waiting for the other player)";
    }
    return s;
}

}  // namespace cdmp::net
