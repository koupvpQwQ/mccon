#include <Windows.h>
#include <intrin.h>

#include "MinHook.h"
#include "probe.h"
#include "log.h"

// ---- 共通 ----

static void LogCaller(const char* name, void* returnAddress)
{
    HMODULE module = nullptr;
    wchar_t path[MAX_PATH] = L"?";

    if (GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(returnAddress),
        &module))
    {
        GetModuleFileNameW(module, path, MAX_PATH);
    }

    Log("[Probe] %s called from %p (module %p, %ls)\n",
        name, returnAddress, module, path);
}

// 最初の数回だけログを出す(毎フレームの呼び出しでログが溢れないように)
static bool ShouldLog(volatile LONG& counter)
{
    return InterlockedIncrement(&counter) <= 3;
}

// ---- GameInputCreate(v0) ----

using GameInputCreate_t = HRESULT(WINAPI*)(void**);
static GameInputCreate_t g_origGameInputCreate = nullptr;
static volatile LONG g_countCreate = 0;

static HRESULT WINAPI Detour_GameInputCreate(void** pp)
{
    void* caller = _ReturnAddress();

    HRESULT hr = g_origGameInputCreate(pp);

    if (ShouldLog(g_countCreate))
    {
        LogCaller("GameInputCreate", caller);
        Log("[Probe]   hr = 0x%08lX, interface = %p\n",
            static_cast<unsigned long>(hr), pp ? *pp : nullptr);
    }

    return hr;
}

// ---- GameInputInitialize(v1以降) ----

using GameInputInitialize_t = HRESULT(WINAPI*)(REFIID, void**);
static GameInputInitialize_t g_origGameInputInitialize = nullptr;
static volatile LONG g_countInitialize = 0;

static HRESULT WINAPI Detour_GameInputInitialize(REFIID riid, void** ppv)
{
    void* caller = _ReturnAddress();

    HRESULT hr = g_origGameInputInitialize(riid, ppv);

    if (ShouldLog(g_countInitialize))
    {
        LogCaller("GameInputInitialize", caller);
        Log("[Probe]   iid = {%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
            riid.Data1, riid.Data2, riid.Data3,
            riid.Data4[0], riid.Data4[1], riid.Data4[2], riid.Data4[3],
            riid.Data4[4], riid.Data4[5], riid.Data4[6], riid.Data4[7]);
        Log("[Probe]   hr = 0x%08lX, interface = %p\n",
            static_cast<unsigned long>(hr), ppv ? *ppv : nullptr);
    }

    return hr;
}

// ---- XInputGetState ----

using XInputGetState_t = DWORD(WINAPI*)(DWORD, void*);
static XInputGetState_t g_origXInputGetState = nullptr;
static volatile LONG g_countXInput = 0;

static DWORD WINAPI Detour_XInputGetState(DWORD index, void* state)
{
    void* caller = _ReturnAddress();

    DWORD result = g_origXInputGetState(index, state);

    if (ShouldLog(g_countXInput))
    {
        LogCaller("XInputGetState", caller);
        Log("[Probe]   index = %lu, result = %lu\n", index, result);
    }

    return result;
}

// ---- DirectInput8Create ----

using DirectInput8Create_t =
HRESULT(WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
static DirectInput8Create_t g_origDirectInput8Create = nullptr;
static volatile LONG g_countDInput = 0;

static HRESULT WINAPI Detour_DirectInput8Create(
    HINSTANCE inst, DWORD version, REFIID riid, LPVOID* ppv, LPUNKNOWN outer)
{
    void* caller = _ReturnAddress();

    HRESULT hr = g_origDirectInput8Create(inst, version, riid, ppv, outer);

    if (ShouldLog(g_countDInput))
    {
        LogCaller("DirectInput8Create", caller);
        Log("[Probe]   hr = 0x%08lX\n", static_cast<unsigned long>(hr));
    }

    return hr;
}

// ---- フックの取り付け ----

struct ProbeTarget
{
    const wchar_t* module;
    const char* function;
    void* detour;
    void** original;
    bool           done;
};

static ProbeTarget g_targets[] =
{
    { L"GameInputRedist.dll", "GameInputCreate",
      reinterpret_cast<void*>(&Detour_GameInputCreate),
      reinterpret_cast<void**>(&g_origGameInputCreate), false },

    { L"GameInputRedist.dll", "GameInputInitialize",
      reinterpret_cast<void*>(&Detour_GameInputInitialize),
      reinterpret_cast<void**>(&g_origGameInputInitialize), false },

    { L"XInput1_4.dll", "XInputGetState",
      reinterpret_cast<void*>(&Detour_XInputGetState),
      reinterpret_cast<void**>(&g_origXInputGetState), false },

    { L"dinput8.dll", "DirectInput8Create",
      reinterpret_cast<void*>(&Detour_DirectInput8Create),
      reinterpret_cast<void**>(&g_origDirectInput8Create), false },
};

static bool TryInstall(ProbeTarget& t)
{
    HMODULE mod = GetModuleHandleW(t.module);

    if (!mod)
        return false;   // まだ読み込まれていない。後で再試行

    t.done = true;

    void* target = GetProcAddress(mod, t.function);

    if (!target)
    {
        Log("[Probe] %s not found\n", t.function);
        return true;
    }

    MH_STATUS status = MH_CreateHook(target, t.detour, t.original);

    if (status != MH_OK)
    {
        Log("[Probe] MH_CreateHook %s FAILED: %s\n",
            t.function, MH_StatusToString(status));
        return true;
    }

    status = MH_EnableHook(target);

    if (status != MH_OK)
    {
        Log("[Probe] MH_EnableHook %s FAILED: %s\n",
            t.function, MH_StatusToString(status));
        return true;
    }

    Log("[Probe] hooked %s at %p\n", t.function, target);

    return true;
}

static DWORD WINAPI ProbeThread(LPVOID)
{
    // 最大120秒、50msごとに、未取り付けのフックを再試行する
    for (int i = 0; i < 2400; i++)
    {
        bool allDone = true;

        for (auto& t : g_targets)
        {
            if (!t.done && !TryInstall(t))
                allDone = false;
        }

        if (allDone)
            return 0;

        Sleep(50);
    }

    for (auto& t : g_targets)
    {
        if (!t.done)
            Log("[Probe] gave up: %ls not loaded\n", t.module);
    }

    return 0;
}

void Probe_Start()
{
    HANDLE thread =
        CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr);

    if (thread)
        CloseHandle(thread);
}