/* Freestanding record counter. The image is analyzed without being executed. */
typedef unsigned int u32;

struct Record {
    u32 category;
    u32 quantity;
};

__attribute__((noinline))
static u32 count_category(const struct Record *records, u32 length, u32 category) {
    u32 total = 0;
    for (u32 i = 0; i < length; ++i) {
        if (records[i].category == category) {
            total += records[i].quantity;
        }
    }
    return total;
}

static const struct Record initial_records[] = {
    {2, 7}, {3, 14}, {2, 19}, {1, 5}, {2, 31},
};

__attribute__((used))
u32 record_entry(u32 category) {
    return count_category(initial_records, 5, category) + 1;
}
