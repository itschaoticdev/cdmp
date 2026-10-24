// Relay transport: room codes, the room cipher, the relay rules and a
// loopback run through a real socket. Included by tests.cpp.

void test_room_code() {
    const auto a = net::generate_room_code();
    const auto b = net::generate_room_code();
    CHECK(a.size() == net::kRoomCodeChars && a != b);
    const auto shown = net::format_room_code(a);
    CHECK(shown.size() == 19 && shown[4] == '-' && shown[9] == '-' && shown[14] == '-');
    CHECK(net::normalize_room_code(shown) == a);
    // What people type: lower case, spaces, O for 0, I/L for 1.
    CHECK(net::normalize_room_code("o1ab cdef-ghjk mnpq") == std::optional<std::string>("01ABCDEFGHJKMNPQ"));
    CHECK(net::normalize_room_code("0IAB-CDEF-GHJK-MNPL") == std::optional<std::string>("01ABCDEFGHJKMNP1"));
    CHECK(!net::normalize_room_code("ABCD-EFGH-JKMN"));        // too short
    CHECK(!net::normalize_room_code("ABCD-EFGH-JKMN-PQRST"));  // too long
    CHECK(!net::normalize_room_code("ABCD-EFGH-JKMN-PQRU"));   // 'U' is not a digit
    CHECK(!net::normalize_room_code("ABCD-EFGH-JKMN-PQR!"));
    // Deterministic, and different codes give different rooms and keys.
    const auto sa = net::derive_room_secrets(a);
    const auto sa2 = net::derive_room_secrets(a);
    const auto sb = net::derive_room_secrets(b);
    CHECK(sa.room_id == sa2.room_id && sa.key == sa2.key);
    CHECK(sa.room_id != sb.room_id && sa.key != sb.key);
}

void test_room_cipher() {
    using D = net::RoomCipher::Direction;
    const auto secrets = net::derive_room_secrets("01ABCDEFGHJKMNPQ");
    net::RoomCipher host, guest;
    CHECK(host.init(secrets, D::HostToGuest) && guest.init(secrets, D::GuestToHost));

    const std::vector<uint8_t> msg = {1, 2, 3, 4, 5, 250};
    std::vector<uint8_t> sealed;
    CHECK(host.seal(msg, sealed) && sealed.size() == msg.size() + net::RoomCipher::kOverhead);
    std::vector<uint8_t> plain(64);
    auto n = guest.open(sealed, plain);
    CHECK(n && *n == msg.size() && std::equal(msg.begin(), msg.end(), plain.begin()));
    CHECK(!guest.open(sealed, plain));  // replay
    CHECK(!host.open(sealed, plain));   // our own datagram reflected back

    // Tampering anywhere (counter, ciphertext, tag) is rejected.
    for (size_t i = 0; i < sealed.size(); ++i) {
        std::vector<uint8_t> s2;
        host.seal(msg, s2);
        s2[i] ^= 0x40;
        CHECK(!guest.open(s2, plain));
    }
    // Another room's key cannot open it.
    net::RoomCipher stranger;
    stranger.init(net::derive_room_secrets("ZZZZZZZZZZZZZZZZ"), D::GuestToHost);
    std::vector<uint8_t> s3;
    host.seal(msg, s3);
    CHECK(!stranger.open(s3, plain));
    CHECK(guest.open(s3, plain));

    // Out of order inside the window is fine, once; older than the window is not.
    std::vector<std::vector<uint8_t>> batch(70);
    for (auto& b : batch) host.seal(msg, b);
    CHECK(guest.open(batch[69], plain));
    CHECK(guest.open(batch[10], plain));   // 59 behind
    CHECK(!guest.open(batch[10], plain));
    CHECK(!guest.open(batch[2], plain));   // 67 behind: too old
    // The other side restarts with the same code: a new session, so no nonce
    // is ever repeated under one key; we follow it, and refuse the old one.
    CHECK(host.session() != guest.session());
    std::vector<uint8_t> old_session;
    guest.seal(msg, old_session);
    CHECK(host.open(old_session, plain));
    net::RoomCipher guest2;
    CHECK(guest2.init(secrets, D::GuestToHost) && guest2.session() != guest.session());
    std::vector<uint8_t> fresh1, fresh2, stale;
    guest2.seal(msg, fresh1);  // counter 1 again, but another session
    CHECK(host.open(fresh1, plain));
    guest.seal(msg, stale);    // the old session, new counter
    CHECK(!host.open(stale, plain));
    guest2.seal(msg, fresh2);
    CHECK(host.open(fresh2, plain));
    // A forged datagram with a made-up session does not move us off the real one.
    std::vector<uint8_t> forged = fresh2;
    forged[0] ^= 1;
    CHECK(!host.open(forged, plain));
    std::vector<uint8_t> fresh3;
    guest2.seal(msg, fresh3);
    CHECK(host.open(fresh3, plain));

    // Too big for the output buffer, or truncated.
    std::vector<uint8_t> tiny(2);
    std::vector<uint8_t> s4;
    host.seal(msg, s4);
    CHECK(!guest.open(s4, tiny));
    CHECK(!guest.open(std::span<const uint8_t>(s4.data(), 10), plain));
}

void test_relay_core() {
    namespace r = net::relay;
    r::RelayCore core;
    std::vector<r::RelayCore::Out> out;
    const auto room = net::derive_room_secrets("01ABCDEFGHJKMNPQ").room_id;
    const net::Endpoint h{0x0100007F, 5000}, g{0x0100007F, 5001}, x{0x0100007F, 5002};
    auto status_of = [&](const r::RelayCore::Out& o) {
        auto f = r::decode(o.bytes);
        return f && f->type == r::Type::JoinAck ? static_cast<int>(f->body[0]) : -1;
    };
    auto type_of = [&](const r::RelayCore::Out& o) {
        auto f = r::decode(o.bytes);
        return f ? f->type : r::Type{};
    };
    uint32_t t = 1000;

    // A guest before any host: no room.
    core.on_datagram(g, r::encode_join(room, r::Role::Guest), t, out);
    CHECK(out.size() == 1 && out[0].to == g && status_of(out[0]) == int(r::Status::NoHost));
    out.clear();
    // A short Join (amplification guard) is ignored.
    auto short_join = r::encode_join(room, r::Role::Host);
    short_join.resize(r::kHeader + 1);
    core.on_datagram(h, short_join, t, out);
    CHECK(out.empty() && core.rooms() == 0);

    core.on_datagram(h, r::encode_join(room, r::Role::Host), t, out);
    CHECK(out.size() == 1 && status_of(out[0]) == int(r::Status::Ok) && core.rooms() == 1);
    out.clear();
    core.on_datagram(g, r::encode_join(room, r::Role::Guest), t, out);
    CHECK(out.size() == 2 && status_of(out[0]) == int(r::Status::Ok));
    CHECK(out.size() == 2 && out[1].to == h && type_of(out[1]) == r::Type::Peer);
    out.clear();
    // Both places taken: another host or guest is refused, nobody is replaced.
    core.on_datagram(x, r::encode_join(room, r::Role::Host), t, out);
    CHECK(out.size() == 1 && status_of(out[0]) == int(r::Status::RoomTaken));
    out.clear();
    core.on_datagram(x, r::encode_join(room, r::Role::Guest), t, out);
    CHECK(out.size() == 1 && status_of(out[0]) == int(r::Status::RoomFull));
    out.clear();

    // Data goes to the other player only, unchanged; strangers are never answered.
    const uint8_t payload[3] = {9, 8, 7};
    core.on_datagram(h, r::encode(r::Type::Data, room, payload), t, out);
    CHECK(out.size() == 1 && out[0].to == g && type_of(out[0]) == r::Type::Forward);
    if (out.size() == 1) {
        auto f = r::decode(out[0].bytes);
        CHECK(f && f->body.size() == 3 && f->body[0] == 9);
    }
    out.clear();
    core.on_datagram(x, r::encode(r::Type::Data, room, payload), t, out);
    CHECK(out.empty());

    // Rate limit: a flood is cut after the burst.
    size_t forwarded = 0;
    for (int i = 0; i < 2000; ++i) {
        core.on_datagram(h, r::encode(r::Type::Data, room, payload), t, out);
        forwarded += out.size();
        out.clear();
    }
    CHECK(forwarded < 1000 && core.stats().rate_limited > 0);

    // The guest goes quiet: freed after the timeout, the host is told, then a new guest fits.
    t += r::RelayCore::kSlotTimeoutMs - 1000;
    core.on_datagram(h, r::encode_join(room, r::Role::Host), t, out);  // the host keeps alive
    out.clear();
    t += 2000;
    core.expire(t, out);
    CHECK(out.size() == 1 && out[0].to == h && type_of(out[0]) == r::Type::Peer);
    out.clear();
    core.on_datagram(x, r::encode_join(room, r::Role::Guest), t, out);
    CHECK(!out.empty() && status_of(out[0]) == int(r::Status::Ok));
    out.clear();
    // The host asking for the guest place in its own room leaves the host place
    // (one place per endpoint), so the room empties instead of holding it twice.
    {
        r::RelayCore c2;
        std::vector<r::RelayCore::Out> o2;
        c2.on_datagram(h, r::encode_join(room, r::Role::Host), t, o2);
        o2.clear();
        c2.on_datagram(h, r::encode_join(room, r::Role::Guest), t, o2);
        CHECK(c2.rooms() == 0 && o2.size() == 1 && status_of(o2[0]) == int(r::Status::NoHost));
    }
    // One address cannot host every room.
    {
        r::RelayCore c3;
        std::vector<r::RelayCore::Out> o3;
        int ok = 0;
        for (uint16_t i = 0; i < 20; ++i) {
            auto id = net::derive_room_secrets(net::generate_room_code()).room_id;
            c3.on_datagram(net::Endpoint{0x0200007F, static_cast<uint16_t>(6000 + i)},
                           r::encode_join(id, r::Role::Host), t, o3);
            ok += status_of(o3.back()) == int(r::Status::Ok);
        }
        CHECK(ok == r::RelayCore::kMaxHostedPerIp && c3.rooms() == size_t(ok));
        // Another address still gets one.
        c3.on_datagram(net::Endpoint{0x0300007F, 7000}, r::encode_join(room, r::Role::Host), t, o3);
        CHECK(status_of(o3.back()) == int(r::Status::Ok));
    }
    // Leaving empties the room.
    core.on_datagram(x, r::encode(r::Type::Leave, room), t, out);
    core.on_datagram(h, r::encode(r::Type::Leave, room), t, out);
    CHECK(core.rooms() == 0);
    // Garbage and other versions are dropped.
    const uint8_t junk[20] = {'C', 'D', 'R', 9};
    out.clear();
    core.on_datagram(h, junk, t, out);
    CHECK(out.empty());
}

void test_relay_transport_loopback() {
    // Two transports through a real relay socket on this PC, plus a stranger
    // with another code.
    if (!net::startup()) {
        CHECK(false);
        return;
    }
    net::UdpSocket relay_sock;
    CHECK(relay_sock.open(0, true));
    const auto relay_ep = net::Endpoint::loopback(relay_sock.local_port());
    net::relay::RelayCore core;
    std::vector<net::relay::RelayCore::Out> out;
    std::vector<uint8_t> rbuf(net::relay::kHeader + net::relay::kMaxPayload + 1);

    const std::string code = net::generate_room_code();
    net::RelayTransport host, guest, intruder;
    CHECK(host.open(relay_ep, code, true));
    CHECK(guest.open(relay_ep, code, false));
    CHECK(intruder.open(relay_ep, net::generate_room_code(), false));

    std::vector<uint8_t> buf(proto::kMaxPacketSize);
    auto pump = [&](uint32_t now) {
        host.poll(now);
        guest.poll(now);
        intruder.poll(now);
        for (int i = 0; i < 64; ++i) {
            net::Endpoint from;
            auto n = relay_sock.recv_from(from, rbuf, 1);
            if (!n) break;
            core.on_datagram(from, {rbuf.data(), *n}, now, out);
        }
        for (const auto& o : out) relay_sock.send_to(o.to, o.bytes);
        out.clear();
    };
    net::PeerAddr from;
    uint32_t now = 1;
    for (int step = 0; step < 50 && !(host.peer_present() && guest.peer_present()); ++step) {
        pump(now += 600);
        host.recv(from, buf, 1);
        guest.recv(from, buf, 1);
        intruder.recv(from, buf, 1);
    }
    CHECK(host.ready() && guest.ready() && host.peer_present() && guest.peer_present());
    CHECK(!intruder.ready());  // another code: nobody hosts that room

    const std::vector<uint8_t> hello = {'h', 'i', 0, 1, 2};
    CHECK(guest.send(net::PeerAddr::relay(), hello));
    std::optional<size_t> got_host;
    for (int step = 0; step < 20 && !got_host; ++step) {
        pump(now += 10);
        got_host = host.recv(from, buf, 5);
    }
    CHECK(got_host && *got_host == hello.size() && from.kind == net::PeerAddr::Kind::Relay &&
          std::equal(hello.begin(), hello.end(), buf.begin()));

    // The biggest packet the session sends still fits after sealing.
    const std::vector<uint8_t> big(proto::kMaxPacketSize, 0xAB);
    CHECK(host.send(net::PeerAddr::relay(), big));
    std::optional<size_t> got_guest;
    for (int step = 0; step < 20 && !got_guest; ++step) {
        pump(now += 10);
        got_guest = guest.recv(from, buf, 5);
    }
    CHECK(got_guest && *got_guest == big.size() && buf[0] == 0xAB && buf[big.size() - 1] == 0xAB);
    CHECK(host.status().find("other player in the room") != std::string::npos);
    net::cleanup();
}
