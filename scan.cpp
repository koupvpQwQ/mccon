#include <Windows.h>
#include <cstring>

#include "scan.h"

uintptr_t GetModuleImageSize(uintptr_t base)
{
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        base + dosHeader->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    return ntHeader->OptionalHeader.SizeOfImage;
}

uintptr_t FindPattern(
    uintptr_t base,
    size_t size,
    const unsigned char* pattern,
    const char* mask,
    size_t* matchCount)
{
    size_t patternLength = strlen(mask);
    uintptr_t first = 0;
    size_t count = 0;

    if (size >= patternLength)
    {
        for (size_t i = 0; i <= size - patternLength; i++)
        {
            bool found = true;

            for (size_t j = 0; j < patternLength; j++)
            {
                if (mask[j] != '?' &&
                    pattern[j] != *reinterpret_cast<const unsigned char*>(
                        base + i + j))
                {
                    found = false;
                    break;
                }
            }

            if (found)
            {
                if (count == 0)
                    first = base + i;

                if (++count >= 2)
                    break;
            }
        }
    }

    if (matchCount)
        *matchCount = count;

    return first;
}