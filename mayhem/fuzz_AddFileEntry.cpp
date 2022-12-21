#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "filelist.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string fileNameStr = provider.ConsumeRandomLengthString();
    std::string aliasStr = provider.ConsumeRandomLengthString();
    const char* fileName = fileNameStr.c_str();
    const char* alias = aliasStr.c_str();
    short windowSize = provider.ConsumeIntegral<short>();
    short hash1Size = provider.ConsumeIntegral<short>();
    short hash2Size = provider.ConsumeIntegral<short>();

    FileListClass flc;
    flc.AddFileEntry(fileName, alias, windowSize, hash1Size, hash2Size);

    return 0;
}