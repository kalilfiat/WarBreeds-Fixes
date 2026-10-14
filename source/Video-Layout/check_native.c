/* Production DLL, actual game ABI thunks, synthetic scene/display. No UI. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
typedef struct {SHORT left,top,right,bottom;} VideoRect;
static BYTE* image;static BYTE* scene;static RECT movie_box;
static UINT resizes,gets,sets;static BOOL fail_resize,fail_scale,port_ready;
static LONG movie_error;
static HMODULE WINAPI mock_module(LPCWSTR name){(void)name;return (HMODULE)image;}
static SHORT __cdecl fake_resize(int w,int h,int colors,int flags){
    ++resizes;if(fail_resize)return 0;
    if(!((w==3840 && h==2160 && colors==65535 && flags==0) || (w==640 && h==480 && colors==256 && flags==1)))return 0;
    *(WORD*)(image+0x1508fc)=(WORD)w;*(WORD*)(image+0x1508fe)=(WORD)h;return 1;
}
LONG __cdecl dispatch(DWORD selector,void* movie,RECT* rectangle){
    if(selector==0x0d){LONG error=movie_error;movie_error=0;return error;}
    if(movie!=(void*)0x1234)return 0;
    if(selector==0x0f){*rectangle=movie_box;++gets;}
    if(selector==0x32){++sets;if(port_ready && !fail_scale)movie_box=*rectangle;else movie_error=-108;}
    return 0;
}
__declspec(naked) void fake_entry(void){
    __asm mov eax,[esp+12]
    __asm mov edx,[esp+16]
    __asm push edx
    __asm push eax
    __asm movzx eax,bx
    __asm push eax
    __asm call dispatch
    __asm add esp,12
    __asm ret
}
static BOOL patch_import(HMODULE module){
    BYTE* b=(BYTE*)module;IMAGE_DOS_HEADER* d=(IMAGE_DOS_HEADER*)b;
    IMAGE_NT_HEADERS32* n=(IMAGE_NT_HEADERS32*)(b+d->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR* desc=(IMAGE_IMPORT_DESCRIPTOR*)(b+n->OptionalHeader.DataDirectory[1].VirtualAddress);
    for(;desc->Name;++desc){
        IMAGE_THUNK_DATA32* lookup=(IMAGE_THUNK_DATA32*)(b+desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA32* iat=(IMAGE_THUNK_DATA32*)(b+desc->FirstThunk);
        for(;lookup->u1.AddressOfData;++lookup,++iat){
            if(!(lookup->u1.Ordinal&IMAGE_ORDINAL_FLAG32)){
                IMAGE_IMPORT_BY_NAME* name=(IMAGE_IMPORT_BY_NAME*)(b+lookup->u1.AddressOfData);
                if(!strcmp((char*)name->Name,"GetModuleHandleW")){
                    DWORD old;VirtualProtect(&iat->u1.Function,4,PAGE_READWRITE,&old);
                    iat->u1.Function=(DWORD)(ULONG_PTR)mock_module;VirtualProtect(&iat->u1.Function,4,old,&old);return TRUE;
                }
            }
        }
    }
    return FALSE;
}
static void setup(void){
    IMAGE_DOS_HEADER* d;IMAGE_NT_HEADERS32* n;DWORD address;
    BYTE thunk[]={0x53,0x66,0xbb,0x0f,0,0xff,0x15,0,0,0,0,0x5b,0xc3};
    BYTE resize[]={0x51,0x57,0xe8,0,0,0,0,0x5a,0x5f,0x59,0xb8,0,0,0,0,0xff,0xe0};
    image=VirtualAlloc(NULL,0x200000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    d=(IMAGE_DOS_HEADER*)image;d->e_magic=IMAGE_DOS_SIGNATURE;d->e_lfanew=0x100;
    n=(IMAGE_NT_HEADERS32*)(image+0x100);n->Signature=IMAGE_NT_SIGNATURE;
    n->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR32_MAGIC;n->OptionalHeader.SizeOfImage=0x200000;
    scene=image+0x180000;*(BYTE**)(image+0x15aea8)=scene;*(HWND*)(image+0x179290)=(HWND)1;
    *(WORD*)(scene+0x28)=640;*(WORD*)(scene+0x2a)=480;*(DWORD*)(scene+0x2c)=65535;
    *(WORD*)(image+0x1508fc)=640;*(WORD*)(image+0x1508fe)=480;*(DWORD*)(image+0x1509c4)=256;
    *(BYTE**)(scene+0x38)=image+0x181000;*(BYTE**)(image+0x181004)=image+0x182000;
    *(DWORD*)(image+0x182000)=0x49564f4d;*(ULONG_PTR*)(image+0x182010)=0x1234;
    address=(DWORD)(ULONG_PTR)(image+0x120f0c);CopyMemory(thunk+7,&address,4);
    CopyMemory(image+0xeaf2d,thunk,sizeof(thunk));thunk[3]=0x32;CopyMemory(image+0xeb0f4,thunk,sizeof(thunk));
    thunk[3]=0x0d;CopyMemory(image+0xeaf13,thunk,sizeof(thunk));
    *(ULONG_PTR*)(image+0x120f0c)=(ULONG_PTR)fake_entry;
    address=(DWORD)(ULONG_PTR)fake_resize;CopyMemory(resize+11,&address,4);CopyMemory(image+0x6fa80,resize,sizeof(resize));
    FlushInstructionCache(GetCurrentProcess(),image,0x200000);
}
#define CHECK(c) do{if(!(c)){printf("failure_line=%d\n",__LINE__);return 1;}++checks;}while(0)
int main(int argc,char** argv){
    HMODULE module;UINT checks=0,i,j;BOOL enabled;VideoRect rectangle;WORD dims[2];
    DWORD (__stdcall *geometry)(DWORD,DWORD,DWORD,DWORD,VideoRect*);
    DWORD (__stdcall *fit)(void*,const WORD*,VideoRect*);
    DWORD (__stdcall *canvas)(void*);DWORD (__stdcall *scale)(void*);DWORD (__stdcall *restore)(void*);
    const WORD sources[][2]={{640,220},{640,200},{320,240},{1920,1080},{800,800}};
    const WORD canvases[][2]={{3840,2160},{1920,1080},{1280,720},{960,540},{640,480}};
    if(argc!=3)return 2;enabled=atoi(argv[2])!=0;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    setup();module=LoadLibraryA(argv[1]);CHECK(module!=NULL);CHECK(patch_import(module));
    geometry=(DWORD (__stdcall*)(DWORD,DWORD,DWORD,DWORD,VideoRect*))GetProcAddress(module,"WBVideoRect");
    fit=(DWORD (__stdcall*)(void*,const WORD*,VideoRect*))GetProcAddress(module,"WBVideoFit");
    canvas=(DWORD (__stdcall*)(void*))GetProcAddress(module,"WBVideoCanvas");
    scale=(DWORD (__stdcall*)(void*))GetProcAddress(module,"WBVideoScale");
    restore=(DWORD (__stdcall*)(void*))GetProcAddress(module,"WBVideoRestore");
    CHECK(geometry!=NULL && fit!=NULL && canvas!=NULL && scale!=NULL && restore!=NULL);
    for(i=0;i<5;++i)for(j=0;j<5;++j){
        CHECK(geometry(sources[i][0],sources[i][1],canvases[j][0],canvases[j][1],&rectangle)==1);
        CHECK(rectangle.left>=0 && rectangle.top>=0 && rectangle.right<=canvases[j][0] && rectangle.bottom<=canvases[j][1]);
        CHECK((rectangle.left&3)==0 && (rectangle.top&3)==0);
    }
    CHECK(geometry(0,200,1920,1080,&rectangle)==0);CHECK(geometry(640,200,0,1080,&rectangle)==0);
    CHECK(geometry(640,200,1920,9000,&rectangle)==0);CHECK(geometry(640,200,1920,1080,NULL)==0);
    CHECK(canvas(scene)==(DWORD)enabled);CHECK(resizes==(enabled?1U:0U));
    if(!enabled){
        dims[0]=640;dims[1]=200;CHECK(fit(scene,dims,&rectangle)==0);CHECK(scale(scene)==0);
        CHECK(gets==0 && sets==0);printf("production_video_checks=%u Enabled=0 game_not_started=1\n",checks);return 0;
    }
    CHECK(*(WORD*)(scene+0x28)==3840 && *(WORD*)(scene+0x2a)==2160);
    for(i=0;i<3;++i){
        dims[0]=sources[i][0];dims[1]=sources[i][1];
        *(WORD*)(image+0x182014)=dims[0];*(WORD*)(image+0x182016)=dims[1];
        movie_box.left=0;movie_box.top=0;movie_box.right=dims[0];movie_box.bottom=dims[1];
        gets=0;sets=0;port_ready=FALSE;
        CHECK(fit(scene,dims,&rectangle)==1);CHECK(gets==0 && sets==0);
        CopyMemory(image+0x181008,&rectangle,sizeof(rectangle));
        port_ready=TRUE;CHECK(scale(scene)==1);CHECK(gets==2 && sets==1);
        CHECK(movie_box.left==rectangle.left && movie_box.top==rectangle.top && movie_box.right==rectangle.right && movie_box.bottom==rectangle.bottom);
        if(i==0)CHECK(rectangle.right-rectangle.left==3840 && rectangle.bottom-rectangle.top==1320 && rectangle.top==420);
        if(i==1)CHECK(rectangle.right-rectangle.left==3840 && rectangle.bottom-rectangle.top==1200 && rectangle.top==480);
        if(i==2)CHECK(rectangle.right-rectangle.left==2880 && rectangle.bottom-rectangle.top==2160 && rectangle.left==480);
    }
    fail_scale=TRUE;CHECK(scale(scene)==0); /* Reject an error even if the box already matches. */
    movie_box.right=320;movie_box.bottom=240;CHECK(scale(scene)==0);CHECK(movie_box.right==320 && movie_box.bottom==240);
    fail_scale=FALSE;CHECK(restore(scene)==1);CHECK(*(WORD*)(scene+0x28)==640 && *(WORD*)(scene+0x2a)==480);
    CHECK(*(WORD*)(image+0x1508fc)==640 && *(WORD*)(image+0x1508fe)==480);CHECK(restore(scene)==0);
    fail_resize=TRUE;CHECK(canvas(scene)==0);
    *(SHORT*)(image+0x11bee8)=-1;CHECK(canvas(scene)==0);
    CHECK(fit(NULL,dims,&rectangle)==0);dims[0]=0;CHECK(fit(scene,dims,&rectangle)==0);
    printf("production_video_checks=%u geometry=ok display_ABI=ok QuickTime_thunks=ok fallback=ok game_not_started=1\n",checks);
    return 0;
}
