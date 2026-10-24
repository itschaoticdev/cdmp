#include "common/room_code.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>

namespace cdmp::net {

namespace {

constexpr char kAlphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";  // Crockford base32

int digit_value(char c) {
    if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    if (c == 'O') c = '0';
    if (c == 'I' || c == 'L') c = '1';
    for (int i = 0; i < 32; ++i) {
        if (kAlphabet[i] == c) return i;
    }
    return -1;
}

std::array<uint8_t, 32> sha256(std::string_view label, const std::string& code) {
    std::array<uint8_t, 32> out{};
    std::string input(label);
    input += code;
    BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0,
               reinterpret_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()),
               out.data(), static_cast<ULONG>(out.size()));
    return out;
}

void put_u64(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<uint8_t>(v);
        v >>= 8;
    }
}

uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

}  // namespace

std::string generate_room_code() {
    uint8_t random[10];
    BCryptGenRandom(nullptr, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    // 80 bits -> 16 groups of 5.
    std::string code;
    uint32_t acc = 0;
    int bits = 0;
    for (uint8_t b : random) {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            code += kAlphabet[(acc >> bits) & 31];
        }
    }
    SecureZeroMemory(random, sizeof random);
    return code;
}

std::optional<std::string> normalize_room_code(std::string_view text) {
    std::string code;
    for (char c : text) {
        if (c == '-' || c == ' ' || c == '\t') continue;
        const int v = digit_value(c);
        if (v < 0) return std::nullopt;
        code += kAlphabet[v];
    }
    if (code.size() != kRoomCodeChars) return std::nullopt;
    return code;
}

std::string format_room_code(const std::string& canonical) {
    std::string out;
    for (size_t i = 0; i < canonical.size(); ++i) {
        if (i && i % 4 == 0) out += '-';
        out += canonical[i];
    }
    return out;
}

RoomSecrets derive_room_secrets(const std::string& canonical) {
    RoomSecrets s;
    const auto id = sha256("cdmp-room-v1", canonical);
    std::memcpy(s.room_id.data(), id.data(), s.room_id.size());
    s.key = sha256("cdmp-key-v1", canonical);
    return s;
}

RoomCipher::~RoomCipher() {
    if (key_) BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(key_));
}

bool RoomCipher::init(const RoomSecrets& secrets, Direction mine) {
    if (key_) {
        BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(key_));
        key_ = nullptr;
    }
    BCRYPT_KEY_HANDLE key = nullptr;
    auto key_bytes = secrets.key;
    const NTSTATUS st = BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &key, nullptr, 0,
                                                   key_bytes.data(), static_cast<ULONG>(key_bytes.size()), 0);
    SecureZeroMemory(key_bytes.data(), key_bytes.size());
    if (!BCRYPT_SUCCESS(st)) return false;
    key_ = key;
    room_id_ = secrets.room_id;
    mine_ = mine;
    send_counter_ = 0;
    recv_highest_ = 0;
    recv_window_ = 0;
    return true;
}

bool RoomCipher::seal(std::span<const uint8_t> plain, std::vector<uint8_t>& out) {
    if (!key_) return false;
    const uint64_t counter = ++send_counter_;
    uint8_t nonce[12] = {static_cast<uint8_t>(mine_)};
    put_u64(nonce + 4, counter);

    const size_t start = out.size();
    out.resize(start + 8 + plain.size() + 16);
    uint8_t* p = out.data() + start;
    put_u64(p, counter);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce;
    info.cbNonce = sizeof nonce;
    info.pbAuthData = room_id_.data();
    info.cbAuthData = static_cast<ULONG>(room_id_.size());
    info.pbTag = p + 8 + plain.size();
    info.cbTag = 16;
    ULONG written = 0;
    const NTSTATUS st = BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(key_),
                                      const_cast<PUCHAR>(plain.data()), static_cast<ULONG>(plain.size()),
                                      &info, nullptr, 0, p + 8, static_cast<ULONG>(plain.size()), &written, 0);
    if (!BCRYPT_SUCCESS(st)) {
        out.resize(start);
        return false;
    }
    return true;
}

std::optional<size_t> RoomCipher::open(std::span<const uint8_t> sealed, std::span<uint8_t> plain_out) {
    if (!key_ || sealed.size() < kOverhead) return std::nullopt;
    const size_t len = sealed.size() - kOverhead;
    if (len > plain_out.size()) return std::nullopt;
    const uint64_t counter = get_u64(sealed.data());
    if (counter == 0) return std::nullopt;

    const auto theirs = mine_ == Direction::HostToGuest ? Direction::GuestToHost : Direction::HostToGuest;
    uint8_t nonce[12] = {static_cast<uint8_t>(theirs)};
    put_u64(nonce + 4, counter);
    uint8_t tag[16];
    std::memcpy(tag, sealed.data() + 8 + len, sizeof tag);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce;
    info.cbNonce = sizeof nonce;
    info.pbAuthData = room_id_.data();
    info.cbAuthData = static_cast<ULONG>(room_id_.size());
    info.pbTag = tag;
    info.cbTag = sizeof tag;
    ULONG written = 0;
    const NTSTATUS st = BCryptDecrypt(static_cast<BCRYPT_KEY_HANDLE>(key_),
                                      const_cast<PUCHAR>(sealed.data() + 8), static_cast<ULONG>(len),
                                      &info, nullptr, 0, plain_out.data(), static_cast<ULONG>(len), &written, 0);
    // Only an authentic datagram may move the replay window.
    if (!BCRYPT_SUCCESS(st) || !accept_counter(counter)) return std::nullopt;
    return len;
}

bool RoomCipher::accept_counter(uint64_t counter) {
    if (counter > recv_highest_) {
        const uint64_t shift = counter - recv_highest_;
        recv_window_ = shift >= 64 ? 0 : recv_window_ << shift;
        recv_window_ |= 1;
        recv_highest_ = counter;
        return true;
    }
    const uint64_t age = recv_highest_ - counter;
    if (age >= 64) return false;
    const uint64_t bit = uint64_t{1} << age;
    if (recv_window_ & bit) return false;
    recv_window_ |= bit;
    return true;
}

}  // namespace cdmp::net
