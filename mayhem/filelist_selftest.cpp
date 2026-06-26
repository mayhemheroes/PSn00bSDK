// filelist_selftest.cpp — behavioral unit test for FileListClass (tools/lzpack/filelist.cpp), the
// code fuzzed by the addfileentry harness. Asserts AddFileEntry actually stores entries with the
// right field values (not just "didn't crash"). Prints SELFTEST_OK on success and exits non-zero on
// any failed assertion (so a neutered/exit(0) build is detected by mayhem/test.sh).
#include <cstdio>
#include <cstring>
#include "filelist.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", (msg)); ++failures; } \
} while (0)

int main(void)
{
    FileListClass flc;

    CHECK(flc.EntryCount() == 0, "fresh list should be empty");

    flc.AddFileEntry("data/level1.bin", "LEVEL1", 13, 4, 3);
    flc.AddFileEntry("data/level2.bin", nullptr, 11, 2, 1);

    CHECK(flc.EntryCount() == 2, "expected 2 entries after two AddFileEntry calls");

    const FileListEntry *e0 = flc.Entry(0);
    CHECK(e0 != nullptr && strcmp(e0->fileName, "data/level1.bin") == 0, "entry0 fileName");
    CHECK(e0 != nullptr && e0->aliasName != nullptr && strcmp(e0->aliasName, "LEVEL1") == 0, "entry0 alias");
    CHECK(e0 != nullptr && e0->windowSize == 13, "entry0 windowSize");
    CHECK(e0 != nullptr && e0->hash1Size == 4, "entry0 hash1Size");
    CHECK(e0 != nullptr && e0->hash2Size == 3, "entry0 hash2Size");

    const FileListEntry *e1 = flc.Entry(1);
    CHECK(e1 != nullptr && strcmp(e1->fileName, "data/level2.bin") == 0, "entry1 fileName");
    CHECK(e1 != nullptr && e1->aliasName == nullptr, "entry1 alias should be NULL");
    CHECK(e1 != nullptr && e1->windowSize == 11, "entry1 windowSize");

    if (failures == 0) {
        printf("SELFTEST_OK\n");
        return 0;
    }
    printf("SELFTEST_FAILED %d\n", failures);
    return 1;
}
