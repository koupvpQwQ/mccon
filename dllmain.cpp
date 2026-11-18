#include <Windows.h>

#include <GameInput.h>

#include "MinHook.h"
#include "log.h"
#include "deadzone.h"
#include "config.h"
#include "probe.h"
#include "gi_probe.h"
#include "diag.h"

static DWORD WINAPI InitializeThread(LPVOID)
{
    Log("[Pad] InitializeThread started\n");

#ifdef GAMEINPUT_API_VERSION
    Log("[Pad] GAMEINPUT_API_VERSION = %d\n", GAMEINPUT_API_VERSION);
#else
    Log("[Pad] GAMEINPUT_API_VERSION undefined\n");
#endif

    MH_STATUS status = MH_Initialize();

    if (status != MH_OK)
    {
        Log(
            "[Pad] MH_Initialize FAILED: %s\n",
            MH_StatusToString(status));

        return 0;
    }

    Log("[Pad] MH_Initialize OK\n");

    Probe_Start();
    GiProbe_Start();

    bool ready = false;

    for (int i = 0; i < 30; i++)
    {
        if (Deadzone_Init())
        {
            ready = true;
            break;
        }

        Sleep(2000);
    }

    if (!ready)
    {
        Log("[Pad] Deadzone_Init gave up\n");
        return 0;
    }

    Log("[Pad] Deadzone original = %f\n", Deadzone_GetOriginal());

    Config_Apply();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        HANDLE thread =
            CreateThread(nullptr, 0, InitializeThread, nullptr, 0, nullptr);

        if (thread)
            CloseHandle(thread);
    }

    return TRUE;
}