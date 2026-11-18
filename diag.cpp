#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <cstring>
#include <cwchar>

#include "diag.h"
#include "log.h"
#include "scan.h"

static bool ContainsNoCase(const char* text, const char* word)
{
    size_t wordLen = strlen(word);

    for (; *text; text++)
    {
        if (_strnicmp(text, word, wordLen) == 0)
            return true;
    }

    return false;
}

static bool ContainsNoCaseW(const wchar_t* text, const wchar_t* word)
{
    size_t wordLen = wcslen(word);

    for (; *text; text++)
    {
        if (_wcsnicmp(text, word, wordLen) == 0)
            return true;
    }

    return false;
}

static void LogImportNames(uintptr_t base, DWORD nameTableRva)
{
    auto thunk =
        reinterpret_cast<PIMAGE_THUNK_DATA64>(base + nameTableRva);

    for (; thunk->u1.AddressOfData; thunk++)
    {
        if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal))
        {
            Log("[Diag]     ordinal %llu\n",
                static_cast<unsigned long long>(
                    IMAGE_ORDINAL64(thunk->u1.Ordinal)));
        }
        else
        {
            auto byName =
                reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                    base + thunk->u1.AddressOfData);

            Log("[Diag]     %s\n", byName->Name);
        }
    }
}

static void LogInputImports()
{
    uintptr_t base =
        reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        base + dos->e_lfanew);

    const auto& importDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.VirtualAddress)
    {
        auto desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
            base + importDir.VirtualAddress);

        for (; desc->Name; desc++)
        {
            const char* dllName =
                reinterpret_cast<const char*>(base + desc->Name);

            if (!ContainsNoCase(dllName, "input"))
                continue;

            Log("[Diag] import dll: %s\n", dllName);

            DWORD table = desc->OriginalFirstThunk
                ? desc->OriginalFirstThunk
                : desc->FirstThunk;

            LogImportNames(base, table);
        }
    }

    const auto& delayDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

    if (delayDir.VirtualAddress)
    {
        auto desc =
            reinterpret_cast<const IMAGE_DELAYLOAD_DESCRIPTOR*>(
                base + delayDir.VirtualAddress);

        for (; desc->DllNameRVA; desc++)
        {
            const char* dllName =
                reinterpret_cast<const char*>(base + desc->DllNameRVA);

            if (!ContainsNoCase(dllName, "input"))
                continue;

            Log("[Diag] delay import dll: %s\n", dllName);

            LogImportNames(base, desc->ImportNameTableRVA);
        }
    }
}

static void LogLoadedInputModules()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        Log("[Diag] snapshot FAILED. Error = %lu\n", GetLastError());
        return;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snapshot, &entry))
    {
        do
        {
            if (ContainsNoCaseW(entry.szModule, L"input"))
            {
                Log("[Diag] module: %ls  (%ls)\n",
                    entry.szModule, entry.szExePath);
            }
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

static void LogGameInputExports()
{
    HMODULE redist = GetModuleHandleW(L"GameInputRedist.dll");

    Log("[Diag] GameInputRedist.dll loaded = %s\n",
        redist ? "yes" : "no");

    if (!redist)
        return;

    Log("[Diag] export GameInputCreate = %p\n",
        reinterpret_cast<void*>(
            GetProcAddress(redist, "GameInputCreate")));

    Log("[Diag] export GameInputInitialize = %p\n",
        reinterpret_cast<void*>(
            GetProcAddress(redist, "GameInputInitialize")));
}

void Diag_LogGameInputInfo()
{
    Log("[Diag] ---- input imports ----\n");
    LogInputImports();

    Log("[Diag] ---- loaded input modules ----\n");
    LogLoadedInputModules();

    Log("[Diag] ---- GameInputRedist exports ----\n");
    LogGameInputExports();

    Log("[Diag] ---- done ----\n");
}
void Diag_ScanGameInputIids()
{
    struct Entry
    {
        const char* name;
        GUID iid;
    };

    static const Entry entries[] =
    {
        { "v0 IGameInput",
          { 0x11BE2A7E, 0x4254, 0x445A,
            { 0x9C, 0x09, 0xFF, 0xC4, 0x0F, 0x00, 0x69, 0x18 } } },

        { "v1 IGameInput",
          { 0x40FFB7E4, 0x6150, 0x407A,
            { 0xB4, 0x39, 0x13, 0x2B, 0xAD, 0xC0, 0x8D, 0x2D } } },

        { "v2 IGameInput",
          { 0xBBAA66D2, 0x837A, 0x40F7,
            { 0xA3, 0x03, 0x91, 0x7D, 0x50, 0x09, 0x55, 0xF4 } } },

        { "v3 IGameInput",
          { 0x20EFC1C7, 0x5D9A, 0x43BA,
            { 0xB2, 0x6F, 0xB8, 0x07, 0xFA, 0x48, 0x60, 0x9C } } },

        { "v4 IGameInput",
          { 0xF2DAAE4C, 0x4D21, 0x4250,
            { 0x89, 0x53, 0x4F, 0x79, 0x1E, 0x62, 0x79, 0xAB } } },
    };

    uintptr_t base =
        reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    uintptr_t size = base ? GetModuleImageSize(base) : 0;

    if (!base || !size)
    {
        Log("[Diag] IID scan: module info FAILED\n");
        return;
    }

    Log("[Diag] ---- IID scan in game image ----\n");

    for (const auto& e : entries)
    {
        size_t count = 0;

        uintptr_t found =
            FindPattern(
                base,
                size,
                reinterpret_cast<const unsigned char*>(&e.iid),
                "xxxxxxxxxxxxxxxx",
                &count);

        Log("[Diag] %s : %s (first = %p, count = %zu)\n",
            e.name,
            found ? "FOUND" : "not found",
            reinterpret_cast<void*>(found),
            count);
    }

    Log("[Diag] ---- IID scan done ----\n");
}