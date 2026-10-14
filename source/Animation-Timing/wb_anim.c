/* Visual clocks only. The game calls these through three narrow drawing hooks. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>

static HINSTANCE instance;
static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
static ULONGLONG epoch;
static UINT cursor_fps = 12, marker_fps = 10;
static BOOL enabled = TRUE;

static UINT bounded_rate(UINT value, UINT fallback) {
    return value >= 5 && value <= 30 ? value : fallback;
}

static BOOL CALLBACK initialize(PINIT_ONCE init, PVOID parameter, PVOID *context) {
    WCHAR path[MAX_PATH];
    DWORD length;
    WCHAR *name;
    const WCHAR filename[] = L"WarBreeds-Animation.ini";
    (void)init; (void)parameter; (void)context;
    length = GetModuleFileNameW(instance, path, MAX_PATH);
    if (length && length < MAX_PATH) {
        name = path + length;
        while (name > path && name[-1] != L'\\' && name[-1] != L'/') --name;
        if ((UINT)(name - path) + sizeof(filename) / sizeof(WCHAR) <= MAX_PATH) {
            CopyMemory(name, filename, sizeof(filename));
            cursor_fps = bounded_rate(GetPrivateProfileIntW(L"Animation", L"CursorFPS", 12, path), 12);
            marker_fps = bounded_rate(GetPrivateProfileIntW(L"Animation", L"MovementRingFPS", 10, path), 10);
            enabled = GetPrivateProfileIntW(L"Animation", L"Enabled", 1, path) != 0;
        }
    }
    epoch = GetTickCount64();
    return TRUE;
}

static void ensure_initialized(void) {
    InitOnceExecuteOnce(&once, initialize, NULL, NULL);
}

DWORD __stdcall WBAnimCursor(DWORD old_counter) {
    ULONGLONG elapsed;
    ensure_initialized();
    if (!enabled) return (old_counter + 1) & 255;
    elapsed = GetTickCount64() - epoch;
    return (DWORD)((elapsed * cursor_fps / 1000) & 255);
}

DWORD __stdcall WBAnimMarker(void) {
    ULONGLONG elapsed;
    ensure_initialized();
    /* The executable hook delegates to the original tick getter when disabled. */
    if (!enabled) return 0xffffffff;
    elapsed = GetTickCount64() - epoch;
    return (DWORD)((elapsed * marker_fps / 1000) & 7) << 1;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) instance = module;
    return TRUE;
}
