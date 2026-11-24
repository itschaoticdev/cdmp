#pragma once
// Finds struct offsets that moved in a game patch by what the data looks like,
// so one wrong offset doesn't take the whole mod down until the next port.
// Used by the mod (in-process reads) and cdmp_probe (remote reads), so the
// memory access is a callable: bool read(uintptr_t addr, void* out, size_t n).

#include <cstdint>
#include <cstring>
#include <optional>
#include <unordered_set>
#include <vector>

#include "common/math3d.h"

namespace cdmp::layout {

inline constexpr uintptr_t kMinPtr = 0x10000;
inline constexpr uintptr_t kMaxPtr = 0x00007FFFFFFFFFFFull;

inline bool plausible_ptr(uintptr_t p) { return p >= kMinPtr && p <= kMaxPtr && p % 8 == 0; }

// A physics transform as the game lays it out: rows X/Y/Z axes at pos-0x30,
// pos-0x20, pos-0x10 (16-byte rows), then the chunk-local position at pos.
inline constexpr uint32_t kAxisXFromPos = 0x30;

struct PhysicsHit {
    size_t root = 0;              // index into the roots passed in
    std::vector<uint32_t> chain;  // pointer fields followed from the root (0-2)
    uint32_t pos_off = 0;         // position offset inside the final object
    uintptr_t object = 0;
};

namespace detail {

inline float f32(const uint8_t* p) {
    float f;
    std::memcpy(&f, p, 4);
    return f;
}

inline proto::Vec3 vec3(const uint8_t* p) { return {f32(p), f32(p + 4), f32(p + 8)}; }

// Is there a transform at buf[pos_off - 0x30 .. pos_off + 0xC) whose position
// plus the chunk origin lands on the player's world position?
inline bool transform_at(const std::vector<uint8_t>& buf, uint32_t pos_off, const proto::Vec3& world,
                         const proto::Vec3& origin, float tol) {
    if (pos_off < kAxisXFromPos || pos_off + 12 > buf.size()) return false;
    const proto::Vec3 local = vec3(buf.data() + pos_off);
    if (!math::is_finite(local)) return false;
    if (math::length(math::sub(math::add(local, origin), world)) > tol) return false;
    const uint8_t* ax = buf.data() + pos_off - kAxisXFromPos;
    return math::is_orthonormal(vec3(ax), vec3(ax + 0x10), vec3(ax + 0x20));
}

template <class Read>
bool read_block(Read& read, uintptr_t addr, std::vector<uint8_t>& buf, size_t n) {
    buf.resize(n);
    if (read(addr, buf.data(), n)) return true;
    // An object near the end of its allocation can sit next to an unreadable
    // page: retry with less.
    buf.resize(n / 2);
    return read(addr, buf.data(), n / 2);
}

}  // namespace detail

struct PhysicsSearch {
    float tolerance = 3.0f;          // metres between local+origin and the world copy
    uint32_t root_span = 0x800;      // pointer fields scanned in each root
    uint32_t middle_span = 0x400;    // pointer fields scanned one hop down
    uint32_t object_span = 0x400;    // bytes of a candidate object checked for a transform
    uint32_t preferred_pos = 0x90;   // try this position offset first in every object
    int max_depth = 2;
};

// Breadth-first: a transform inside a root, then one pointer down, then two.
// Within a depth the roots are tried in the order given, so put the likeliest
// first. Returns the first match.
template <class Read>
std::optional<PhysicsHit> find_physics(Read&& read, const std::vector<uintptr_t>& roots, const proto::Vec3& world,
                                       const proto::Vec3& origin, const PhysicsSearch& s = {}) {
    std::vector<uint8_t> obj, mid, top;
    std::unordered_set<uintptr_t> seen;

    auto check = [&](uintptr_t addr) -> std::optional<uint32_t> {
        if (!plausible_ptr(addr) || !seen.insert(addr).second) return std::nullopt;
        if (!detail::read_block(read, addr, obj, s.object_span)) return std::nullopt;
        if (detail::transform_at(obj, s.preferred_pos, world, origin, s.tolerance)) return s.preferred_pos;
        for (uint32_t pos = kAxisXFromPos; pos + 12 <= obj.size(); pos += 0x10) {
            if (detail::transform_at(obj, pos, world, origin, s.tolerance)) return pos;
        }
        return std::nullopt;
    };
    auto ptr_at = [](const std::vector<uint8_t>& b, size_t i) {
        uintptr_t v;
        std::memcpy(&v, b.data() + i, 8);
        return v;
    };

    for (size_t r = 0; r < roots.size(); ++r) {
        if (auto pos = check(roots[r])) return PhysicsHit{r, {}, *pos, roots[r]};
    }
    if (s.max_depth < 1) return std::nullopt;
    for (size_t r = 0; r < roots.size(); ++r) {
        if (!plausible_ptr(roots[r]) || !detail::read_block(read, roots[r], top, s.root_span)) continue;
        for (size_t a = 0; a + 8 <= top.size(); a += 8) {
            const uintptr_t p = ptr_at(top, a);
            if (auto pos = check(p)) return PhysicsHit{r, {static_cast<uint32_t>(a)}, *pos, p};
        }
    }
    if (s.max_depth < 2) return std::nullopt;
    std::unordered_set<uintptr_t> expanded;
    for (size_t r = 0; r < roots.size(); ++r) {
        if (!plausible_ptr(roots[r]) || !detail::read_block(read, roots[r], top, s.root_span)) continue;
        for (size_t a = 0; a + 8 <= top.size(); a += 8) {
            const uintptr_t m = ptr_at(top, a);
            if (!plausible_ptr(m) || !expanded.insert(m).second) continue;
            if (!detail::read_block(read, m, mid, s.middle_span)) continue;
            for (size_t b = 0; b + 8 <= mid.size(); b += 8) {
                const uintptr_t p = ptr_at(mid, b);
                // Objects already rejected at depth 1 stay in `seen` and are
                // skipped by check(): no transform is in them.
                if (auto pos = check(p))
                    return PhysicsHit{r, {static_cast<uint32_t>(a), static_cast<uint32_t>(b)}, *pos, p};
            }
        }
    }
    return std::nullopt;
}

struct CameraHit {
    uint32_t block_off = 0;     // pointer field in the camera object
    uint32_t sentinel_off = 0;  // where the sentinel float sits in the block
    uintptr_t block = 0;
};

// Every (block pointer, sentinel offset) pair in the camera object whose block
// holds the sentinel float, in field order. The caller validates the rest.
template <class Read>
std::vector<CameraHit> find_camera_blocks(Read&& read, uintptr_t camera, float sentinel, uint32_t camera_span = 0x800,
                                          uint32_t block_span = 0x1400) {
    std::vector<CameraHit> hits;
    std::vector<uint8_t> top, block;
    if (!plausible_ptr(camera) || !detail::read_block(read, camera, top, camera_span)) return hits;
    std::unordered_set<uintptr_t> seen;
    for (size_t a = 0; a + 8 <= top.size(); a += 8) {
        uintptr_t p;
        std::memcpy(&p, top.data() + a, 8);
        if (!plausible_ptr(p) || !seen.insert(p).second) continue;
        if (!detail::read_block(read, p, block, block_span)) continue;
        for (size_t i = 0; i + 4 <= block.size(); i += 4) {
            if (detail::f32(block.data() + i) == sentinel)
                hits.push_back({static_cast<uint32_t>(a), static_cast<uint32_t>(i), p});
        }
    }
    return hits;
}

}  // namespace cdmp::layout
