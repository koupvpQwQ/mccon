#pragma once

#include <cstdint>
#include <cstddef>

uintptr_t GetModuleImageSize(uintptr_t base);

// 最初のマッチ位置を返す。matchCountには見つかった数(最大2)を入れる
uintptr_t FindPattern(
    uintptr_t base,
    size_t size,
    const unsigned char* pattern,
    const char* mask,
    size_t* matchCount = nullptr);