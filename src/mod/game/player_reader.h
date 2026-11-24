#pragma once
// Reads the local player's state from game memory (read-only). Re-resolves the
// whole pointer chain on every call and validates each hop by vtable, so it
// keeps working across loading screens and simply returns nullopt while the
// player is not in the world (title screen, loading).

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/protocol.h"

namespace cdmp::game {

struct PlayerSnapshot {
    proto::Vec3 position;        // world space (chunk origin applied); Y is up
    proto::Vec3 local_position;  // physics position, relative to the map chunk
    proto::Vec3 chunk_origin;    // world = local + chunk_origin
    proto::Quat rotation;
    float health = 0.0f;         // NaN-free; 0/0 if stats could not be read
    float health_max = 0.0f;
    float stamina = 0.0f;
    float stamina_max = 0.0f;
    float static_pos_error = 0;  // distance to the game's own world-pos global
};

class PlayerReader {
public:
    // Checks the exe build. If it is not the one our offsets are for, the
    // reader stays disabled for the whole session.
    bool init();
    bool enabled() const { return enabled_; }

    std::optional<PlayerSnapshot> read();

    // The player's ClientCharacterControlActorComponent (vtable-checked).
    std::optional<uintptr_t> character_control();

    // Why the last read() returned nullopt, for logging.
    const std::string& last_failure() const { return last_failure_; }

private:
    // How to get from the CharacterControl component to the player's physics
    // transform. Starts as the ported offsets; relocate() replaces it when the
    // game build moved them (found by matching the game's world-pos copy).
    struct PhysicsPath {
        bool from_control = false;     // false: start at [control + kControl_Inner]
        std::vector<uint32_t> chain;   // pointer fields to follow
        uint32_t pos_off = 0;          // axes X/Y/Z at -0x30/-0x20/-0x10
    };
    struct Transform {
        proto::Vec3 local, ax, ay, az;
    };
    static constexpr float kRelocateDistance = 25.0f;  // m off the world copy = wrong object
    static constexpr uint64_t kFarOffMs = 5'000;

    std::optional<Transform> read_transform(uintptr_t control, uintptr_t inner);
    bool relocate(uintptr_t control, uintptr_t inner, const proto::Vec3& origin,
                  const std::optional<proto::Vec3>& world);
    static std::string describe(const PhysicsPath& p);
    std::optional<uintptr_t> resolve_actor();
    void read_stats(uintptr_t components, PlayerSnapshot& out);
    std::nullopt_t fail(const char* why);

    bool enabled_ = false;
    uintptr_t base_ = 0;
    std::string last_failure_;
    PhysicsPath path_;
    bool relocated_ = false;
    uint64_t next_search_ms_ = 0;
    int searches_ = 0;
    uint64_t far_since_ms_ = 0;
};

}  // namespace cdmp::game
