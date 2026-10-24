// cdmp_relay.exe - the relay for transport=relay: players join a room with a
// room code instead of being Steam friends. It forwards sealed datagrams
// between the two players of each room and never sees what they say.
//
//   cdmp_relay [--port 37020] [--loopback] [--quiet]
//
// --loopback listens on 127.0.0.1 only (tests on one PC).

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "common/clock.h"
#include "common/relay.h"
#include "common/udp.h"

using namespace cdmp;

namespace {

volatile bool g_stop = false;

BOOL WINAPI on_ctrl(DWORD) {
    g_stop = true;
    return TRUE;
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port = 37020;
    bool loopback = false;
    bool quiet = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (a == "--loopback") {
            loopback = true;
        } else if (a == "--quiet") {
            quiet = true;
        } else {
            std::printf("cdmp_relay [--port 37020] [--loopback] [--quiet]\n");
            return a == "--help" || a == "-h" ? 0 : 1;
        }
    }

    if (!net::startup()) {
        std::fprintf(stderr, "Winsock startup failed\n");
        return 1;
    }
    net::UdpSocket sock;
    if (!sock.open(port, loopback)) {
        std::fprintf(stderr, "cannot listen on UDP %u: %s\n", port, net::UdpSocket::last_error().c_str());
        return 2;
    }
    SetConsoleCtrlHandler(on_ctrl, TRUE);
    std::printf("cdmp relay on UDP %u%s (protocol %u)\n", port, loopback ? " (loopback only)" : "",
                net::relay::kVersion);
    std::fflush(stdout);

    net::relay::RelayCore core;
    std::vector<net::relay::RelayCore::Out> out;
    std::vector<uint8_t> buf(net::relay::kHeader + net::relay::kMaxPayload + 1);
    uint32_t last_expire = now_ms();
    uint32_t last_report = now_ms();
    size_t last_rooms = 0;

    while (!g_stop) {
        net::Endpoint from;
        if (auto n = sock.recv_from(from, buf, 200)) {
            core.on_datagram(from, {buf.data(), *n}, now_ms(), out);
        }
        const uint32_t now = now_ms();
        if (now - last_expire >= 1000) {
            last_expire = now;
            core.expire(now, out);
        }
        for (const auto& o : out) sock.send_to(o.to, o.bytes);
        out.clear();

        if (!quiet && (now - last_report >= 60000 || core.rooms() != last_rooms)) {
            last_report = now;
            last_rooms = core.rooms();
            const auto& st = core.stats();
            std::printf("rooms %zu  forwarded %llu  dropped %llu  rate-limited %llu\n", core.rooms(),
                        static_cast<unsigned long long>(st.forwarded), static_cast<unsigned long long>(st.dropped),
                        static_cast<unsigned long long>(st.rate_limited));
            std::fflush(stdout);
        }
    }
    sock.close();
    net::cleanup();
    return 0;
}
