// load_transform.h: finding the Transform in a character load packet.
// Included from tests.cpp inside its anonymous namespace.

// pos | quat | scale (1,1,1) | parent, at index `at`.
void put_load_transform(std::vector<uint8_t>& b, size_t at, float x, float y, float z, bool parent_none = true) {
    const float f[10] = {x, y, z, 0.0f, 0.7071068f, 0.0f, 0.7071068f, 1.0f, 1.0f, 1.0f};
    std::memcpy(b.data() + at, f, sizeof f);
    std::memset(b.data() + at + 40, parent_none ? 0xFF : 0x12, 8);
}

void test_load_transform() {
    namespace lt = cdmp::load_transform;
    {   // 2976 layout: position 154 bytes before the end.
        std::vector<uint8_t> b(2000, 0x55);
        put_load_transform(b, b.size() - 154, -10644.7f, 618.3f, -3825.0f);
        const auto f = lt::find(b);
        CHECK(f && f->pos_from_end == 154 && f->known);
    }
    {   // A patch added 20 bytes after it: found by shape.
        std::vector<uint8_t> b(2000, 0x55);
        put_load_transform(b, b.size() - 174, -10644.7f, 618.3f, -3825.0f);
        const auto f = lt::find(b);
        CHECK(f && f->pos_from_end == 174 && !f->known);
        float p[3];
        CHECK(lt::read_pos(b, f->pos_from_end, p) && p[0] == -10644.7f && p[2] == -3825.0f);
    }
    {   // Two Transforms: the unparented one nearest the end wins over a parented later one.
        std::vector<uint8_t> b(2000, 0x55);
        put_load_transform(b, b.size() - 300, 10.0f, 20.0f, 30.0f, true);
        put_load_transform(b, b.size() - 120, 40.0f, 50.0f, 60.0f, false);
        const auto f = lt::find(b);
        CHECK(f && f->pos_from_end == 300);
    }
    {   // Garbage where the old offset was and nowhere a Transform: none.
        std::vector<uint8_t> b(2000, 0x00);
        CHECK(!lt::find(b));
        std::vector<uint8_t> c(2000, 0xFF);  // NaN floats
        CHECK(!lt::find(c));
    }
    {   // Scale not 1 / rotation not unit: not a Transform.
        std::vector<uint8_t> b(2000, 0x55);
        put_load_transform(b, b.size() - 154, 1.0f, 2.0f, 3.0f);
        const float bad = 9.0f;
        std::memcpy(b.data() + b.size() - 154 + lt::kScaleFromPos, &bad, 4);
        CHECK(!lt::looks_like_transform(b, b.size() - 154));
    }
    {   // Parked default character is still found (the capture skips it by position).
        std::vector<uint8_t> b(600, 0x55);
        put_load_transform(b, b.size() - 154, 0.0f, 1000.0f, 0.0f);
        float p[3];
        const auto f = lt::find(b);
        CHECK(f && lt::read_pos(b, f->pos_from_end, p) && p[1] == 1000.0f);
    }
    {   // Short packet.
        std::vector<uint8_t> b(30, 0x55);
        CHECK(!lt::find(b));
    }
}
