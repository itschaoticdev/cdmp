#pragma once
// Transport through tools/relay with a room code: no Steam friendship, no
// port forwarding, and neither player sees the other's IP. Everything the
// session sends is sealed with the room key before it leaves the PC.

#include <cstdint>
#include <string>

#include "common/relay.h"
#include "common/room_code.h"
#include "common/transport.h"

namespace cdmp::net {

class RelayTransport final : public Transport {
public:
    RelayTransport() = default;
    ~RelayTransport() override { leave(); }  // frees our place now, not after the relay's timeout
    RelayTransport(const RelayTransport&) = delete;
    RelayTransport& operator=(const RelayTransport&) = delete;

    // code: canonical room code (normalize_room_code). host: we hold the room.
    bool open(const Endpoint& relay, const std::string& code, bool host);

    bool send(const PeerAddr& to, std::span<const uint8_t> data) override;
    std::optional<size_t> recv(PeerAddr& from, std::span<uint8_t> buf, int timeout_ms) override;
    void poll(uint32_t now_ms) override;
    bool ready() const override { return joined_; }
    std::string status() const override;

    bool peer_present() const { return peer_present_; }
    void leave();

private:
    // A frame from the relay; true (and n) when it carried the other player's data.
    bool handle(std::span<const uint8_t> bytes, std::span<uint8_t> buf, size_t& n);

    UdpSocket sock_;
    Endpoint relay_;
    std::string code_;
    RoomSecrets secrets_;
    RoomCipher cipher_;
    bool host_ = false;
    bool joined_ = false;
    bool peer_present_ = false;
    relay::Status last_status_ = relay::Status::Ok;
    uint32_t last_join_ms_ = 0;
    uint32_t last_heard_ms_ = 0;
    uint32_t now_ms_ = 0;
    std::vector<uint8_t> scratch_;
};

}  // namespace cdmp::net
