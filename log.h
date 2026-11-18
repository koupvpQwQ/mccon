#pragma once

#include <Windows.h>
#include <cstdio>
#include <cstdarg>

inline void Log(const char* format, ...)
{
    char buffer[512];

    va_list args;
    va_start(args, format);
    vsprintf_s(buffer, sizeof(buffer), format, args);
    va_end(args);

    OutputDebugStringA(buffer);
}