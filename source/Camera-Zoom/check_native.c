/* Tests the production DLL with a deterministic Windows-clock import. No UI. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        if (!memcmp(section->Name, ".wbzoom", 7)) {
            MEMORY_BASIC_INFORMATION info;
            if (VirtualQuery((BYTE *)image + section->VirtualAddress, &info, sizeof(info)) != sizeof(info)) break;
            found = (info.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }
    }
    FreeLibrary(image);
    return found;
}


int main(int argc,char**argv){
    HMODULE m;DWORD (__stdcall *decide)(int,DWORD,DWORD);DWORD (__stdcall *pump)(void);
    UINT on,inv,mode;int delta,i;DWORD wanted,got;UINT count=0;
    if(argc!=5)return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    m=LoadLibraryA(argv[1]);if(!m)return 3;
    decide=(DWORD (__stdcall *)(int,DWORD,DWORD))GetProcAddress(m,"WBZoomDecision");
    pump=(DWORD (__stdcall *)(void))GetProcAddress(m,"WBZoomPump");
    if(!decide||!pump)return 4;on=(UINT)atoi(argv[2]);inv=(UINT)atoi(argv[3]);
    for(mode=0;mode<2;++mode)for(delta=-360;delta<=360;delta+=30){
        int effective=inv?-delta:delta;
        decide(0,mode,0);
        wanted=0xffffffff;
        if(on && effective>=120 && mode==1)wanted=0;
        if(on && effective<=-120 && mode==0)wanted=1;
        got=decide(delta,mode,1);
        if(got!=wanted){printf("decision_error mode=%u delta=%d got=%lu expected=%lu\n",mode,delta,got,wanted);return 5;}
        ++count;
    }
    for(mode=0;mode<2;++mode){
        decide(0,mode,0);
        for(i=0;i<4;++i){
            delta=inv?-30:30;
            wanted=(on && mode==1 && i==3)?0:0xffffffff;
            if(decide(delta,mode,1)!=wanted)return 6;
            ++count;
        }
        if(decide(-120,mode,0)!=0xffffffff || decide(120,2,1)!=0xffffffff)return 7;
        count+=2;
        /* A full opposite wheel event after context loss must not inherit leftovers. */
        decide(30,mode,1);decide(0,mode,0);
        if(decide(inv?-90:90,mode,1)!=0xffffffff)return 8;
        ++count;
    }
    if(pump()!=0)return 9; // This helper is not WARBREED.EXE: no OS hook is installed.
    if(!validate_image(argv[4]))return 10;
    printf("native_wheel_cases=%u enabled=%u invert=%u PE_mapping=ok game_not_started=1\n",count,on,inv);
    FreeLibrary(m);return 0;
}
