#include <Windows.h>
#include <cmath>

#include "deadzone.h"
#include "log.h"
#include "scan.h"

static float* g_deadzone = nullptr;
static float  g_original = 0.0f;

bool Deadzone_Init()
{
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    uintptr_t size = base ? GetModuleImageSize(base) : 0;

    if (!base || !size)
    {
        Log("[Deadzone] module info FAILED\n");
        return false;
    }

    // movss xmm6,[rip+?] / movss xmm7,[rip+?] / xorps xmm11,xmm11
    const unsigned char pattern[] =
    {
        0xF3, 0x0F, 0x10, 0x35, 0x00, 0x00, 0x00, 0x00,
        0xF3, 0x0F, 0x10, 0x3D, 0x00, 0x00, 0x00, 0x00,
        0x45, 0x0F, 0x57, 0xDB
    };

    const char mask[] = "xxxx????xxxx????xxxx";

    size_t count = 0;
    uintptr_t match = FindPattern(base, size, pattern, mask, &count);

    Log("[Deadzone] Pattern matches = %zu\n", count);

    if (!match)
        return false;

    uintptr_t movssAddress = match + 8;

    int32_t displacement =
        *reinterpret_cast<int32_t*>(movssAddress + 4);

    float* target =
        reinterpret_cast<float*>(movssAddress + 8 + displacement);

    float value = *target;

    Log("[Deadzone] Target = %p, value = %f\n",
        reinterpret_cast<void*>(target), value);

    if (!(value > 0.2f && value < 0.6f))
    {
        Log("[Deadzone] value out of expected range, abort\n");
        return false;
    }

    g_deadzone = target;
    g_original = value;

    return true;
}

bool Deadzone_Set(float value)
{
    if (!g_deadzone)
        return false;

    if (value < 0.0f)  value = 0.0f;
    if (value > 0.99f) value = 0.99f;

    DWORD oldProtect = 0;

    if (!VirtualProtect(
        g_deadzone, sizeof(float), PAGE_READWRITE, &oldProtect))
    {
        Log("[Deadzone] VirtualProtect FAILED. Error = %lu\n",
            GetLastError());
        return false;
    }

    *g_deadzone = value;

    DWORD dummy = 0;
    VirtualProtect(g_deadzone, sizeof(float), oldProtect, &dummy);

    return true;
}

float Deadzone_GetOriginal()
{
    return g_original;
}