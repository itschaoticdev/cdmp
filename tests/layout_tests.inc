// layout_search.h: finding moved struct offsets in fake memory.
// Included from tests.cpp inside its anonymous namespace.

struct FakeMemory {
    std::vector<std::pair<uintptr_t, std::vector<uint8_t>>> regions;
    FakeMemory() { regions.reserve(16); }  // add() hands out references

    std::vector<uint8_t>& add(uintptr_t at, size_t size) {
        regions.push_back({at, std::vector<uint8_t>(size, 0)});
        return regions.back().second;
    }
    bool operator()(uintptr_t addr, void* out, size_t n) const {
        for (const auto& [at, bytes] : regions) {
            if (addr >= at && addr + n <= at + bytes.size()) {
                std::memcpy(out, bytes.data() + (addr - at), n);
                return true;
            }
        }
        return false;
    }
};

void put_ptr(std::vector<uint8_t>& b, size_t off, uintptr_t v) { std::memcpy(b.data() + off, &v, 8); }
void put_vec(std::vector<uint8_t>& b, size_t off, float x, float y, float z) {
    const float f[3] = {x, y, z};
    std::memcpy(b.data() + off, f, sizeof f);
}
// Identity basis at pos-0x30.., position at pos.
void put_transform(std::vector<uint8_t>& b, size_t pos, proto::Vec3 local) {
    put_vec(b, pos - 0x30, 1, 0, 0);
    put_vec(b, pos - 0x20, 0, 1, 0);
    put_vec(b, pos - 0x10, 0, 0, 1);
    put_vec(b, pos, local.x, local.y, local.z);
}

void test_layout_physics_search() {
    const proto::Vec3 origin{-9000, 0, -3000};
    const proto::Vec3 local{-740.5f, 611.6f, -952.0f};
    const proto::Vec3 world{-9740.5f, 611.6f, -3952.0f};
    {
        // One hop: the field moved from inner+0x2C0 to +0x2C8; the old field
        // points at an object without a transform (the 3732 report).
        FakeMemory m;
        auto& control = m.add(0x100000, 0x800);
        auto& inner = m.add(0x200000, 0x800);
        auto& physics = m.add(0x300000, 0x400);
        m.add(0x400000, 0x400);
        put_ptr(control, 0x140, 0x200000);
        put_ptr(inner, 0x2C0, 0x400000);
        put_ptr(inner, 0x2C8, 0x300000);
        put_transform(physics, 0xA0, local);
        auto hit = layout::find_physics(m, {0x200000, 0x100000}, world, origin);
        CHECK(hit && hit->root == 0 && hit->chain == (std::vector<uint32_t>{0x2C8}) && hit->pos_off == 0xA0 &&
              hit->object == 0x300000);
    }
    {
        // Two hops: inner -> handle -> physics.
        FakeMemory m;
        auto& control = m.add(0x100000, 0x800);
        auto& inner = m.add(0x200000, 0x800);
        auto& handle = m.add(0x500000, 0x400);
        auto& physics = m.add(0x600000, 0x400);
        put_ptr(control, 0x140, 0x200000);
        put_ptr(inner, 0x2C0, 0x500000);
        put_ptr(handle, 0x18, 0x600000);
        put_transform(physics, 0x90, local);
        auto hit = layout::find_physics(m, {0x200000, 0x100000}, world, origin);
        CHECK(hit && hit->root == 0 && hit->chain == (std::vector<uint32_t>{0x2C0, 0x18}) && hit->pos_off == 0x90);
        // Not allowed that deep: nothing.
        layout::PhysicsSearch shallow;
        shallow.max_depth = 1;
        CHECK(!layout::find_physics(m, {0x200000, 0x100000}, world, origin, shallow));
    }
    {
        // Right position but not a rotation in front of it, or the wrong
        // position: no match. A cycle back to the root must not loop.
        FakeMemory m;
        auto& inner = m.add(0x200000, 0x800);
        auto& a = m.add(0x300000, 0x400);
        auto& b = m.add(0x400000, 0x400);
        put_ptr(inner, 0x10, 0x300000);
        put_ptr(inner, 0x18, 0x400000);
        put_ptr(inner, 0x20, 0x200000);
        put_ptr(a, 0x8, 0x200000);
        put_vec(a, 0x90, local.x, local.y, local.z);  // axes all zero
        put_transform(b, 0x90, {local.x + 10, local.y, local.z});
        CHECK(!layout::find_physics(m, {0x200000}, world, origin));
        // Within the tolerance it is found.
        layout::PhysicsSearch loose;
        loose.tolerance = 11.0f;
        auto hit = layout::find_physics(m, {0x200000}, world, origin, loose);
        CHECK(hit && hit->object == 0x400000);
    }
    {
        // Two transforms in one object: the preferred offset wins.
        FakeMemory m;
        auto& obj = m.add(0x300000, 0x400);
        put_transform(obj, 0x50, local);
        put_transform(obj, 0x90, local);
        auto hit = layout::find_physics(m, {0x300000}, world, origin);
        CHECK(hit && hit->chain.empty() && hit->pos_off == 0x90);
        layout::PhysicsSearch other;
        other.preferred_pos = 0x200;
        hit = layout::find_physics(m, {0x300000}, world, origin, other);
        CHECK(hit && hit->pos_off == 0x50);
    }
    {
        // An object at the end of its allocation (next page unreadable): the
        // shorter retry still finds it. Null and bogus roots are skipped.
        FakeMemory m;
        auto& inner = m.add(0x200000, 0x800);
        auto& small = m.add(0x700000, 0x200);
        put_ptr(inner, 0x30, 0x700000);
        put_transform(small, 0x90, local);
        auto hit = layout::find_physics(m, {0, 0x123, 0x200000}, world, origin);
        CHECK(hit && hit->root == 2 && hit->chain == (std::vector<uint32_t>{0x30}));
    }
}

void test_layout_camera_search() {
    FakeMemory m;
    auto& camera = m.add(0x100000, 0x800);
    auto& block = m.add(0x200000, 0x1400);
    auto& other = m.add(0x300000, 0x1400);
    put_ptr(camera, 0x428, 0x300000);
    put_ptr(camera, 0x430, 0x200000);
    const float s = 6360000.0f;
    std::memcpy(block.data() + 0xAD0, &s, 4);
    auto hits = layout::find_camera_blocks(m, 0x100000, s);
    CHECK(hits.size() == 1 && hits[0].block_off == 0x430 && hits[0].sentinel_off == 0xAD0 && hits[0].block == 0x200000);
    std::memcpy(other.data() + 0xAC0, &s, 4);
    hits = layout::find_camera_blocks(m, 0x100000, s);
    CHECK(hits.size() == 2 && hits[0].block_off == 0x428 && hits[1].block_off == 0x430);
    CHECK(layout::find_camera_blocks(m, 0, s).empty());
}
