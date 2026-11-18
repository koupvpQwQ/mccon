#include <Windows.h>
#include <intrin.h>
#include <cmath>

#include "MinHook.h"
#include "gi_probe.h"
#include "log.h"

// vtable: 0:QueryInterface 1:AddRef 2:Release
//         3:GetCurrentTimestamp 4:GetCurrentReading(v0とv2で共通)
static const int kSlotGetCurrentReading = 4;

using GetCurrentReading_t =
HRESULT(STDMETHODCALLTYPE*)(
    void* self, UINT32 inputKind, void* device, void** reading);

static GetCurrentReading_t g_origV0 = nullptr;
static GetCurrentReading_t g_origV2 = nullptr;
static volatile LONG g_countV0 = 0;
static volatile LONG g_countV2 = 0;

static void LogAddress(const char* label, void* address)
{
    HMODULE module = nullptr;
    wchar_t path[MAX_PATH] = L"?";

    if (GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(address),
        &module))
    {
        GetModuleFileNameW(module, path, MAX_PATH);
    }

    Log("[GiProbe] %s = %p (module %p, %ls)\n",
        label, address, module, path);
}

// 最初の5回と、その後は600回ごとにログを出す
static bool ShouldLogCall(LONG n)
{
    return n <= 5 || (n % 600) == 0;
}

static HRESULT STDMETHODCALLTYPE Detour_V0(
    void* self, UINT32 inputKind, void* device, void** reading)
{
    void* caller = _ReturnAddress();

    HRESULT hr = g_origV0(self, inputKind, device, reading);

    LONG n = InterlockedIncrement(&g_countV0);

    if (ShouldLogCall(n))
    {
        Log("[GiProbe] v0 GetCurrentReading #%ld kind=0x%X hr=0x%08lX reading=%p\n",
            n, inputKind, static_cast<unsigned long>(hr),
            reading ? *reading : nullptr);

        LogAddress("v0 caller", caller);
    }

    return hr;
}

static void** volatile g_gamepadVtable = nullptr;

static SRWLOCK g_kindLock = SRWLOCK_INIT;
static UINT32  g_seenKinds[16] = {};
static int     g_seenKindCount = 0;

// 初めて見た種別ならtrueを返す
static bool MarkKindSeen(UINT32 kind)
{
    bool added = false;

    AcquireSRWLockExclusive(&g_kindLock);

    bool found = false;

    for (int i = 0; i < g_seenKindCount; i++)
    {
        if (g_seenKinds[i] == kind)
        {
            found = true;
            break;
        }
    }

    if (!found && g_seenKindCount < 16)
    {
        g_seenKinds[g_seenKindCount++] = kind;
        added = true;
    }

    ReleaseSRWLockExclusive(&g_kindLock);

    return added;
}

static HRESULT STDMETHODCALLTYPE Detour_V2(
    void* self, UINT32 inputKind, void* device, void** reading)
{
    void* caller = _ReturnAddress();

    HRESULT hr = g_origV2(self, inputKind, device, reading);

    InterlockedIncrement(&g_countV2);

    // ゲームパッド種別のreadingから、vtableを1回だけ記録する
    if (SUCCEEDED(hr) && reading && *reading &&
        (inputKind & 0x40000) && !g_gamepadVtable)
    {
        g_gamepadVtable = *reinterpret_cast<void***>(*reading);
    }

    if (MarkKindSeen(inputKind))
    {
        Log("[GiProbe] v2 GetCurrentReading new kind=0x%X hr=0x%08lX reading=%p\n",
            inputKind, static_cast<unsigned long>(hr),
            reading ? *reading : nullptr);

        LogAddress("v2 caller", caller);
    }

    return hr;
}

static bool HookMethod(const char* label, void* target, void* detour, void** original)
{
    MH_STATUS status = MH_CreateHook(target, detour, original);

    if (status != MH_OK)
    {
        Log("[GiProbe] MH_CreateHook %s FAILED: %s\n",
            label, MH_StatusToString(status));
        return false;
    }

    status = MH_EnableHook(target);

    if (status != MH_OK)
    {
        Log("[GiProbe] MH_EnableHook %s FAILED: %s\n",
            label, MH_StatusToString(status));
        return false;
    }

    Log("[GiProbe] hooked %s\n", label);
    return true;
}

// GameInputGamepadState の想定レイアウト(buttons + float 6個)。
// 値が不自然に見える場合は教えてください
struct GamepadStateRaw
{
    UINT32 buttons;
    float  leftTrigger;
    float  rightTrigger;
    float  leftThumbstickX;
    float  leftThumbstickY;
    float  rightThumbstickX;
    float  rightThumbstickY;
};

// IGameInputReading(v2) の vtable: 18 = GetGamepadState
static const int kSlotGetGamepadState = 18;

using GetGamepadState_t =
bool(STDMETHODCALLTYPE*)(void* self, GamepadStateRaw* state);

static GetGamepadState_t g_origGetGamepadState = nullptr;
static volatile LONG g_countGamepadState = 0;
static volatile LONG64 g_lastStateLog = 0;

static bool STDMETHODCALLTYPE Detour_GetGamepadState(
    void* self, GamepadStateRaw* state)
{
    void* caller = _ReturnAddress();

    bool ok = g_origGetGamepadState(self, state);

    LONG n = InterlockedIncrement(&g_countGamepadState);

    if (n <= 3)
    {
        Log("[GiProbe] GetGamepadState #%ld ok=%d\n", n, ok ? 1 : 0);
        LogAddress("GetGamepadState caller", caller);
    }

    if (ok && state)
    {
        const float threshold = 0.02f;

        bool active =
            state->buttons != 0 ||
            fabsf(state->leftTrigger) > threshold ||
            fabsf(state->rightTrigger) > threshold ||
            fabsf(state->leftThumbstickX) > threshold ||
            fabsf(state->leftThumbstickY) > threshold ||
            fabsf(state->rightThumbstickX) > threshold ||
            fabsf(state->rightThumbstickY) > threshold;

        LONG64 now = static_cast<LONG64>(GetTickCount64());
        LONG64 last = g_lastStateLog;

        // 入力があるときだけ、250msに1回ログを出す
        if (active && now - last >= 250 &&
            InterlockedCompareExchange64(&g_lastStateLog, now, last) == last)
        {
            Log("[GiProbe] pad buttons=0x%08X LT=%.3f RT=%.3f L=(%.3f,%.3f) R=(%.3f,%.3f)\n",
                state->buttons,
                state->leftTrigger, state->rightTrigger,
                state->leftThumbstickX, state->leftThumbstickY,
                state->rightThumbstickX, state->rightThumbstickY);
        }
    }

    return ok;
}
static DWORD WINAPI GiProbeThread(LPVOID)
{
    // GameInputRedist.dll の読み込みを最大60秒待つ
    HMODULE redist = nullptr;

    for (int i = 0; i < 1200 && !redist; i++)
    {
        redist = GetModuleHandleW(L"GameInputRedist.dll");

        if (!redist)
            Sleep(50);
    }

    if (!redist)
    {
        Log("[GiProbe] GameInputRedist.dll not loaded\n");
        return 0;
    }

    using Create_t = HRESULT(WINAPI*)(void**);

    auto create = reinterpret_cast<Create_t>(
        GetProcAddress(redist, "GameInputCreate"));

    if (!create)
    {
        Log("[GiProbe] GameInputCreate not found\n");
        return 0;
    }

    // v0 のインターフェース(ヘッダーの GameInputLegacy 相当)
    void* legacy = nullptr;
    HRESULT hr = create(&legacy);

    Log("[GiProbe] GameInputCreate hr=0x%08lX legacy=%p\n",
        static_cast<unsigned long>(hr), legacy);

    if (FAILED(hr) || !legacy)
        return 0;

    // v2 のインターフェースを QueryInterface で取得
    static const GUID kIidV2 =
    { 0xBBAA66D2, 0x837A, 0x40F7,
      { 0xA3, 0x03, 0x91, 0x7D, 0x50, 0x09, 0x55, 0xF4 } };

    using QueryInterface_t =
        HRESULT(STDMETHODCALLTYPE*)(void*, REFIID, void**);

    void** vtblV0 = *reinterpret_cast<void***>(legacy);

    auto queryInterface = reinterpret_cast<QueryInterface_t>(vtblV0[0]);

    void* v2 = nullptr;
    hr = queryInterface(legacy, kIidV2, &v2);

    Log("[GiProbe] QueryInterface(v2) hr=0x%08lX v2=%p\n",
        static_cast<unsigned long>(hr), v2);

    void* fnV0 = vtblV0[kSlotGetCurrentReading];
    void* fnV2 = nullptr;

    if (SUCCEEDED(hr) && v2)
    {
        void** vtblV2 = *reinterpret_cast<void***>(v2);
        fnV2 = vtblV2[kSlotGetCurrentReading];
    }

    LogAddress("v0 GetCurrentReading", fnV0);
    LogAddress("v2 GetCurrentReading", fnV2);

    // 取得した参照は意図的に解放しない(プロセス終了まで保持)
    if (fnV0)
    {
        HookMethod("v0 GetCurrentReading", fnV0,
            reinterpret_cast<void*>(&Detour_V0),
            reinterpret_cast<void**>(&g_origV0));
    }

    if (fnV2 && fnV2 != fnV0)
    {
        HookMethod("v2 GetCurrentReading", fnV2,
            reinterpret_cast<void*>(&Detour_V2),
            reinterpret_cast<void**>(&g_origV2));
    }
    else if (fnV2)
    {
        Log("[GiProbe] v2 and v0 share the same function\n");
    }

    Log("[GiProbe] ready\n");

    // ゲームパッド種別のreadingが1回でも返るのを待つ(最大120秒)
    for (int i = 0; i < 2400 && !g_gamepadVtable; i++)
        Sleep(50);

    if (!g_gamepadVtable)
    {
        Log("[GiProbe] no gamepad reading captured\n");
        return 0;
    }

    void* fnState = g_gamepadVtable[kSlotGetGamepadState];

    LogAddress("v2 reading GetGamepadState", fnState);

    HookMethod("v2 GetGamepadState", fnState,
        reinterpret_cast<void*>(&Detour_GetGamepadState),
        reinterpret_cast<void**>(&g_origGetGamepadState));

    return 0;
}
void GiProbe_Start()
{
    HANDLE thread =
        CreateThread(nullptr, 0, GiProbeThread, nullptr, 0, nullptr);

    if (thread)
        CloseHandle(thread);
}