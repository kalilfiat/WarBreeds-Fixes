/* Tests the production DLL with a deterministic Windows-clock import. No UI. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ULONGLONG current_time = 0xfffffff0ULL;
static ULONGLONG WINAPI test_clock(void) { return current_time; }

static BOOL replace_clock(HMODULE module) {
    BYTE *base = (BYTE *)module;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(base + dos->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR *)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (; imports->Name; ++imports) {
        IMAGE_THUNK_DATA32 *names = (IMAGE_THUNK_DATA32 *)(base + imports->OriginalFirstThunk);
        IMAGE_THUNK_DATA32 *addresses = (IMAGE_THUNK_DATA32 *)(base + imports->FirstThunk);
        if (!imports->OriginalFirstThunk) continue;
        for (; names->u1.AddressOfData; ++names, ++addresses) {
            IMAGE_IMPORT_BY_NAME *name;
            DWORD protection, ignored;
            if (IMAGE_SNAP_BY_ORDINAL32(names->u1.Ordinal)) continue;
            name = (IMAGE_IMPORT_BY_NAME *)(base + names->u1.AddressOfData);
            if (strcmp((char *)name->Name, "GetTickCount64")) continue;
            if (!VirtualProtect(&addresses->u1.Function, sizeof(DWORD), PAGE_READWRITE, &protection)) return FALSE;
            addresses->u1.Function = (DWORD)(ULONG_PTR)test_clock;
            VirtualProtect(&addresses->u1.Function, sizeof(DWORD), protection, &ignored);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL validate_image(const char *path) {
    HMODULE image;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS32 *nt;
    IMAGE_SECTION_HEADER *section;
    WORD index;
    BOOL found = FALSE;
    image = LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!image) { printf("PE_map_error=%lu\n", GetLastError()); return FALSE; }
    dos = (IMAGE_DOS_HEADER *)image;
    nt = (IMAGE_NT_HEADERS32 *)((BYTE *)image + dos->e_lfanew);
    section = IMAGE_FIRST_SECTION(nt);
    for (index = 0; index < nt->FileHeader.NumberOfSections; ++index, ++section) {
        if (!memcmp(section->Name, ".wbanim", 7)) {
            MEMORY_BASIC_INFORMATION info;
            if (VirtualQuery((BYTE *)image + section->VirtualAddress, &info, sizeof(info)) != sizeof(info)) break;
            found = (info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }
    }
    FreeLibrary(image);
    return found;
}

int main(int argc, char **argv) {
    HMODULE module;
    DWORD (__stdcall *cursor)(DWORD);
    DWORD (__stdcall *marker)(void);
    UINT cursor_rate, marker_rate, enabled, index;
    ULONGLONG epoch;
    const ULONGLONG samples[] = {0, 1, 66, 83, 99, 100, 250, 500, 999, 1000,
                                65535, 1234567, 0x100000000ULL, 0x10000007bULL, 0x10000000000ULL};
    if (argc != 6 && argc != 5) return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    module = LoadLibraryA(argv[1]);
    if (!module) { printf("DLL_load_error=%lu\n", GetLastError()); return 3; }
    cursor = (DWORD (__stdcall *)(DWORD))GetProcAddress(module, "WBAnimCursor");
    marker = (DWORD (__stdcall *)(void))GetProcAddress(module, "WBAnimMarker");
    if (!cursor || !marker || !replace_clock(module)) return 4;
    cursor_rate = (UINT)atoi(argv[2]); marker_rate = (UINT)atoi(argv[3]); enabled = (UINT)atoi(argv[4]);
    epoch = current_time;
    if (cursor(123) != (enabled ? 0UL : 124UL)) return 5;
    for (index = 0; index < sizeof(samples) / sizeof(samples[0]); ++index) {
        DWORD old = index == 0 ? 255 : 123;
        DWORD actual_cursor, actual_marker, expected_cursor, expected_marker;
        current_time = epoch + samples[index];
        actual_cursor = cursor(old); actual_marker = marker();
        expected_cursor = enabled ? (DWORD)((samples[index] * cursor_rate / 1000) & 255) : (old + 1) & 255;
        expected_marker = enabled ? (DWORD)((samples[index] * marker_rate / 1000) & 7) << 1 : 0xffffffff;
        if (actual_cursor != expected_cursor || actual_marker != expected_marker) {
            printf("Mismatch sample=%u cursor=%lu/%lu marker=%lu/%lu\n", index,
                   actual_cursor, expected_cursor, actual_marker, expected_marker);
            return 6;
        }
    }
    if (argc == 6 && !validate_image(argv[5])) return 7;
    printf("native_clock_pairs=15 cursor_fps=%u marker_fps=%u enabled=%u PE_mapping=ok\n",
           cursor_rate, marker_rate, enabled);
    FreeLibrary(module);
    return 0;
}
