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
        if (!memcmp(section->Name, ".wbui", 5)) {
            MEMORY_BASIC_INFORMATION info;
            if (VirtualQuery((BYTE *)image + section->VirtualAddress, &info, sizeof(info)) != sizeof(info)) break;
            found = (info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }
    }
    FreeLibrary(image);
    return found;
}


int main(int argc,char **argv) {
    HMODULE module;
    DWORD (__stdcall *advance)(ULONG_PTR,DWORD);
    ULONGLONG start=current_time, next[2]={0,0};
    UINT rate[2], enabled, i, c, count=0;
    if(argc!=6)return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    module=LoadLibraryA(argv[1]);if(!module)return 3;
    advance=(DWORD (__stdcall *)(ULONG_PTR,DWORD))GetProcAddress(module,"WBUIAdvance");
    if(!advance||!replace_clock(module))return 4;
    rate[0]=(UINT)atoi(argv[2]);rate[1]=(UINT)atoi(argv[3]);enabled=(UINT)atoi(argv[4]);
    for(i=0;i<=1000;i+=2){
        current_time=start+i;
        for(c=0;c<2;++c){
            DWORD wanted=!enabled||i>=next[c], got=advance(100+c,c);
            if(got!=wanted){printf("gate_error t=%u ch=%u actual=%lu expected=%lu\n",i,c,got,wanted);return 5;}
            if(wanted)next[c]=i+(1000+rate[c]-1)/rate[c];
            ++count;
        }
    }
    /* A long pause resets once, with no catch-up burst. */
    current_time=start+10000;
    if(advance(100,0)!=1 || advance(100,0)!=(enabled?0UL:1UL))return 6;
    current_time=start+0x100000000ULL;
    if(advance(100,0)!=1)return 7;
    current_time=start; if(advance(100,0)!=1)return 8;
    if(advance(0,0)!=1||advance(1,2)!=1)return 9;
    for(i=1;i<=300;++i)if(advance(i+1000,0)!=1)return 10;
    if(!validate_image(argv[5]))return 11;
    printf("native_gate_checks=%u rates=%u/%u enabled=%u PE_mapping=ok\n",count+308,rate[0],rate[1],enabled);
    FreeLibrary(module);return 0;
}
