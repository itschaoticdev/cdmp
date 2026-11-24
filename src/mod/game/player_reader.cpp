#include "mod/game/player_reader.h"

#include <windows.h>

#include <cmath>

#include <format>

#include "common/layout_search.h"
#include "common/math3d.h"
#include "mod/game/offsets.h"
#include "mod/game/safe_memory.h"
#include "mod/log.h"

namespace cdmp::game {
namespace off = build_3732;

namespace {

std::optional<proto::Vec3> read_vec3(uintptr_t addr) {
    float f[3];
    if (!safe_read(addr, f, sizeof f)) return std::nullopt;
    proto::Vec3 v{f[0], f[1], f[2]};
    if (!math::is_finite(v)) return std::nullopt;
    return v;
}

}  // namespace

bool PlayerReader::init() {
    base_ = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base_ + dos->e_lfanew);
    enabled_ = base_ == off::kImageBase && nt->FileHeader.TimeDateStamp == off::kPeTimestamp;
    if (!enabled_) last_failure_ = "unsupported game build";
    path_ = {false, {off::kControlInner_Physics}, off::kPhysics_Position};
    static_assert(off::kPhysics_Position - off::kPhysics_AxisX == layout::kAxisXFromPos);
    static_assert(off::kPhysics_AxisY == off::kPhysics_AxisX + 0x10 && off::kPhysics_AxisZ == off::kPhysics_AxisX + 0x20);
    return enabled_;
}

std::nullopt_t PlayerReader::fail(const char* why) {
    last_failure_ = why;
    return std::nullopt;
}

std::optional<uintptr_t> PlayerReader::resolve_actor() {
    auto world = read_ptr(base_ + off::kWorldSystemSlot);
    if (!world) return fail("WorldSystem not created");
    auto manager = read_ptr(*world + off::kWorldSystem_ActorManager);
    if (!manager || !has_vtable(*manager, base_ + off::kVtClientActorManager))
        return fail("ClientActorManager missing");
    auto actor = read_ptr(*manager + off::kActorManager_ControlledActor);
    if (!actor) return fail("no controlled actor (not in world)");
    if (!has_vtable(*actor, base_ + off::kVtControlledActor))
        return fail("controlled actor has unexpected type");
    return actor;
}

std::optional<uintptr_t> PlayerReader::character_control() {
    if (!enabled_) return fail("unsupported game build");
    auto actor = resolve_actor();
    if (!actor) return std::nullopt;
    auto components = read_ptr(*actor + off::kActor_ComponentTable);
    if (!components) return fail("component table missing");
    auto control = read_ptr(*components + off::kComponents_CharacterControl);
    if (!control || !has_vtable(*control, base_ + off::kVtCharacterControl))
        return fail("CharacterControl component missing");
    return control;
}

std::optional<PlayerSnapshot> PlayerReader::read() {
    if (!enabled_) return fail("unsupported game build");

    auto actor = resolve_actor();
    if (!actor) return std::nullopt;

    auto components = read_ptr(*actor + off::kActor_ComponentTable);
    if (!components) return fail("component table missing");
    auto control = read_ptr(*components + off::kComponents_CharacterControl);
    if (!control || !has_vtable(*control, base_ + off::kVtCharacterControl))
        return fail("CharacterControl component missing");
    const uintptr_t inner = read_ptr(*control + off::kControl_Inner).value_or(0);
    auto origin = read_vec3(base_ + off::kChunkOrigin);
    auto world = read_vec3(base_ + off::kStaticPlayerPos);
    if (!origin) return fail("chunk origin unreadable");

    auto t = read_transform(*control, inner);
    // A wrong path either reads garbage or a transform that isn't ours: both
    // send us looking for the real one (throttled inside).
    // The world copy lags a fast travel by a moment, so "far off" has to last
    // a few seconds before it counts (else a stale copy could be matched).
    const bool far_off = t && world && math::length(math::sub(math::add(t->local, *origin), *world)) > kRelocateDistance;
    const uint64_t now = GetTickCount64();
    if (!far_off) far_since_ms_ = 0;
    else if (!far_since_ms_) far_since_ms_ = now;
    const bool wrong = !t || (far_off && now - far_since_ms_ > kFarOffMs);
    if (wrong && relocate(*control, inner, *origin, world)) t = read_transform(*control, inner);
    if (!t) return std::nullopt;  // read_transform set last_failure_

    PlayerSnapshot snap;
    snap.position = math::add(t->local, *origin);
    snap.local_position = t->local;
    snap.chunk_origin = *origin;
    snap.rotation = math::quat_from_axes(t->ax, t->ay, t->az);

    // The game keeps its own world-space copy; a large mismatch means our
    // chunk-origin math or chain is off (it lags by a frame, so allow some).
    if (world) snap.static_pos_error = math::length(math::sub(snap.position, *world));

    // While a save loads, the game parks the actor at (0, 1000, 0) for tens
    // of seconds before placing it. Don't broadcast that as a real position.
    if (std::fabs(snap.position.x) < off::kLoadingParkRadius &&
        std::fabs(snap.position.z) < off::kLoadingParkRadius &&
        std::fabs(snap.position.y - off::kLoadingParkHeight) < off::kLoadingParkRadius) {
        return fail("loading (actor parked at 0,1000,0)");
    }

    read_stats(*components, snap);
    last_failure_.clear();
    return snap;
}

std::optional<PlayerReader::Transform> PlayerReader::read_transform(uintptr_t control, uintptr_t inner) {
    uintptr_t obj = path_.from_control ? control : inner;
    if (!obj) return fail("control inner missing");
    for (uint32_t off : path_.chain) {
        auto next = read_ptr(obj + off);
        if (!next) return fail("physics object missing");
        obj = *next;
    }
    // kVtPhysicsObject was ported offline (no RTTI) and is not verified in game
    // yet: a mismatch is logged once and the orthonormal basis check below is
    // then the only type check. 0 = not known for this build.
    if (!relocated_ && off::kVtPhysicsObject && !has_vtable(obj, base_ + off::kVtPhysicsObject)) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            uintptr_t vt = 0;
            safe_read(obj, &vt, sizeof vt);
            log::warn("Player reader: physics vtable exe+0x{:X}, expected exe+0x{:X} (please report)",
                      vt - base_, off::kVtPhysicsObject);
        }
    }
    const uintptr_t pos = obj + path_.pos_off;
    auto local = read_vec3(pos);
    auto ax = read_vec3(pos - layout::kAxisXFromPos);
    auto ay = read_vec3(pos - layout::kAxisXFromPos + 0x10);
    auto az = read_vec3(pos - layout::kAxisXFromPos + 0x20);
    if (!local || !ax || !ay || !az) return fail("physics data unreadable");
    if (!math::is_orthonormal(*ax, *ay, *az)) return fail("physics basis not a rotation");
    return Transform{*local, *ax, *ay, *az};
}

std::string PlayerReader::describe(const PhysicsPath& p) {
    std::string s = p.from_control ? "control" : std::format("control+0x{:X}", off::kControl_Inner);
    for (uint32_t off : p.chain) s += std::format(" -> +0x{:X}", off);
    return s + std::format(", position +0x{:X}", p.pos_off);
}

bool PlayerReader::relocate(uintptr_t control, uintptr_t inner, const proto::Vec3& origin,
                            const std::optional<proto::Vec3>& world) {
    // Needs the game's own world-space copy to match against, and not the
    // loading park (every object of the actor sits there while loading).
    if (!world || math::length(*world) < 1.0f) return false;
    if (std::fabs(world->x) < off::kLoadingParkRadius && std::fabs(world->z) < off::kLoadingParkRadius) return false;
    const uint64_t now = GetTickCount64();
    if (now < next_search_ms_) return false;
    next_search_ms_ = now + (searches_ < 6 ? 5'000 : 30'000);
    ++searches_;

    auto read = [](uintptr_t a, void* out, size_t n) { return safe_read(a, out, n); };
    auto hit = layout::find_physics(read, {inner, control}, *world, origin);
    const uint64_t took = GetTickCount64() - now;
    if (!hit) {
        if (searches_ == 1 || searches_ % 10 == 0)
            log::warn("Player reader: searched for the physics object ({} ms, try {}), not found (please report)", took,
                      searches_);
        return false;
    }
    PhysicsPath found{hit->root == 1, hit->chain, hit->pos_off};
    if (found.from_control == path_.from_control && found.chain == path_.chain && found.pos_off == path_.pos_off)
        return false;
    uintptr_t vt = 0;
    safe_read(hit->object, &vt, sizeof vt);
    log::info("Player reader: physics object found at {} (vtable exe+0x{:X}, {} ms); was {}. Please report this line.",
              describe(found), vt - base_, took, describe(path_));
    path_ = std::move(found);
    relocated_ = true;
    return true;
}

void PlayerReader::read_stats(uintptr_t components, PlayerSnapshot& out) {
    auto status = read_ptr(components + off::kComponents_Status);
    if (!status || !has_vtable(*status, base_ + off::kVtStatusComponent)) return;
    auto container = read_ptr(*status + off::kStatus_StatContainer);
    if (!container) return;
    auto entries = read_ptr(*container + off::kStatContainer_Entries);
    auto count = game::read<uint32_t>(*container + off::kStatContainer_Count);
    if (!entries || !count || *count > off::kMaxStatEntries) return;

    // Look stats up by id: the entry order changes between patches.
    for (uint32_t i = 0; i < *count; ++i) {
        const uintptr_t e = *entries + static_cast<uintptr_t>(i) * off::kStatEntry_Size;
        auto id = game::read<uint64_t>(e + off::kStatEntry_Id);
        if (!id) continue;
        float* cur_out = nullptr;
        float* max_out = nullptr;
        if (*id == off::kStatId_Health) {
            cur_out = &out.health;
            max_out = &out.health_max;
        } else if (*id == off::kStatId_Stamina) {
            cur_out = &out.stamina;
            max_out = &out.stamina_max;
        } else {
            continue;
        }
        auto cur = game::read<int64_t>(e + off::kStatEntry_Current);
        auto max = game::read<int64_t>(e + off::kStatEntry_Max);
        if (!cur || !max || *max <= 0 || *cur < 0 || *cur > *max) continue;
        *cur_out = static_cast<float>(*cur) / 1000.0f;
        *max_out = static_cast<float>(*max) / 1000.0f;
    }
}

}  // namespace cdmp::game
