#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>

static HINSTANCE instance;
static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
static BOOL enabled = TRUE;
static UINT rates[2] = {12, 12};
typedef struct { ULONG_PTR key; DWORD channel; ULONGLONG next, seen; } Clock;
static Clock clocks[256];
static SRWLOCK lock = SRWLOCK_INIT;

static BOOL CALLBACK initialize(PINIT_ONCE init, PVOID arg, PVOID *ctx) {
    WCHAR path[MAX_PATH], *name;
    const WCHAR filename[] = L"WarBreeds-UI.ini";
    DWORD length = GetModuleFileNameW(instance, path, MAX_PATH);
    UINT i;
    (void)init; (void)arg; (void)ctx;
    if (length && length < MAX_PATH) {
        name = path + length;
        while (name > path && name[-1] != L'\\' && name[-1] != L'/') --name;
        if ((UINT)(name - path) + sizeof(filename)/sizeof(WCHAR) <= MAX_PATH) {
            CopyMemory(name, filename, sizeof(filename));
            enabled = GetPrivateProfileIntW(L"UIAnimation", L"Enabled", 1, path) != 0;
            rates[0] = GetPrivateProfileIntW(L"UIAnimation", L"HologramFPS", 12, path);
            rates[1] = GetPrivateProfileIntW(L"UIAnimation", L"PanelFPS", 12, path);
            for (i=0; i<2; ++i) if (rates[i] < 5 || rates[i] > 30) rates[i] = 12;
        }
    }
    return TRUE;
}

/* Called only around decorative HQ cycles and Gene Lab panel jitter.
   Button handlers, drawing and simulation clocks continue on their original paths. */
DWORD __stdcall WBUIAdvance(ULONG_PTR key, DWORD channel) {
    ULONGLONG now, oldest = ~(ULONGLONG)0;
    UINT i, slot = 0;
    DWORD allow = 0;
    InitOnceExecuteOnce(&once, initialize, NULL, NULL);
    if (!enabled || !key || channel > 1) return 1;
    now = GetTickCount64();
    AcquireSRWLockExclusive(&lock);
    for (i=0; i<256; ++i) {
        if (clocks[i].key == key && clocks[i].channel == channel) { slot=i; break; }
        if (!clocks[i].key) { oldest=0; slot=i; }
        else if (oldest && clocks[i].seen < oldest) { oldest=clocks[i].seen; slot=i; }
    }
    if (i==256 || now < clocks[slot].seen || now-clocks[slot].seen > 2000) {
        clocks[slot].key=key; clocks[slot].channel=channel;
        clocks[slot].next=now;
    }
    if (now >= clocks[slot].next) {
        /* No catch-up burst after a pause, loading screen or slow frame. */
        clocks[slot].next=now+(1000+rates[channel]-1)/rates[channel];
        allow=1;
    }
    clocks[slot].seen=now;
    ReleaseSRWLockExclusive(&lock);
    return allow;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason==DLL_PROCESS_ATTACH) instance=module;
    return TRUE;
}
