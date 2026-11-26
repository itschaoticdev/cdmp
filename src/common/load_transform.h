#pragma once
// Where the Transform sits inside an ActorLoadDataAck payload (the packet the
// mod copies to load the other player's character).
//
// The Transform is position (3 floats), rotation quaternion (4 floats), scale
// (3 floats, 1.0 for characters), then an 8-byte parent key (all FF = none).
// On 1.0.0.2976 the position of the player's Transform was always 154 bytes
// before the end of the payload. A patch that adds a field after it moves
// that, and writing our position at a stale offset corrupts the packet (live
// test 2026-11-25 on 3732: the host crashed loading the guest). So the
// offset is checked against what a Transform looks like, and searched for
// when it doesn't match.

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

namespace cdmp::load_transform {

inline constexpr size_t kKnownPosFromEnd = 154;  // 1.0.0.2976 .. 3460
inline constexpr size_t kRotFromPos = 12;
inline constexpr size_t kScaleFromPos = 28;
inline constexpr size_t kParentFromPos = 40;
inline constexpr size_t kTransformSize = 40;     // pos + rot + scale
inline constexpr size_t kSearchWindow = 1024;    // bytes before the end searched
inline constexpr float kMaxCoord = 1.0e6f;
inline constexpr float kMaxHeight = 1.0e5f;

inline float f32_at(const uint8_t* p) {
    float f;
    std::memcpy(&f, p, 4);
    return f;
}

// A Transform starts at `pos` (index from the start of the payload).
inline bool looks_like_transform(const std::vector<uint8_t>& v, size_t pos) {
    if (pos + kTransformSize > v.size()) return false;
    const uint8_t* p = v.data() + pos;
    const float x = f32_at(p), y = f32_at(p + 4), z = f32_at(p + 8);
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) return false;
    if (std::fabs(x) > kMaxCoord || std::fabs(z) > kMaxCoord || std::fabs(y) > kMaxHeight) return false;
    // All-zero memory passes the coordinate test; a real position is not (0,0,0).
    if (x == 0.0f && y == 0.0f && z == 0.0f) return false;
    float n = 0;
    for (int i = 0; i < 4; ++i) {
        const float q = f32_at(p + kRotFromPos + 4 * i);
        if (!std::isfinite(q)) return false;
        n += q * q;
    }
    if (std::fabs(n - 1.0f) > 0.02f) return false;
    for (int i = 0; i < 3; ++i) {
        const float s = f32_at(p + kScaleFromPos + 4 * i);
        if (!std::isfinite(s) || s < 0.5f || s > 2.0f) return false;
    }
    return true;
}

inline bool parent_is_none(const std::vector<uint8_t>& v, size_t pos) {
    if (pos + kParentFromPos + 8 > v.size()) return false;
    for (size_t i = 0; i < 8; ++i) {
        if (v[pos + kParentFromPos + i] != 0xFF) return false;
    }
    return true;
}

struct Found {
    size_t pos_from_end = 0;  // payload.size() - index of the position
    bool known = false;       // the 2976 offset still holds
};

// The player's Transform: the known offset when it still looks like one,
// else the last Transform in the tail of the payload (one with no parent
// preferred: the player's own Transform has none unless riding).
inline std::optional<Found> find(const std::vector<uint8_t>& v) {
    if (v.size() >= kKnownPosFromEnd && looks_like_transform(v, v.size() - kKnownPosFromEnd)) {
        return Found{kKnownPosFromEnd, true};
    }
    if (v.size() < kTransformSize) return std::nullopt;
    const size_t lo = v.size() > kSearchWindow ? v.size() - kSearchWindow : 0;
    std::optional<size_t> any, unparented;
    for (size_t i = v.size() - kTransformSize + 1; i-- > lo;) {
        if (!looks_like_transform(v, i)) continue;
        if (!any) any = i;
        if (parent_is_none(v, i)) {
            unparented = i;
            break;
        }
    }
    const auto at = unparented ? unparented : any;
    if (!at) return std::nullopt;
    return Found{v.size() - *at, false};
}

inline bool read_pos(const std::vector<uint8_t>& v, size_t pos_from_end, float out[3]) {
    if (pos_from_end > v.size() || pos_from_end < 12) return false;
    std::memcpy(out, v.data() + v.size() - pos_from_end, 12);
    return true;
}

}  // namespace cdmp::load_transform
