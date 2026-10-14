/* Exercise the PRODUCTION DLL bootstrap and queued-message callback in an
   isolated host. Windows imports and native game entrypoints are mocked in
   this helper process only. No window, input injection or game is started. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <string.h>

static BYTE* image;
static HOOKPROC callback;
static UINT installs, resizes, zooms, clamps, next_calls;
static BOOL foreground=TRUE, fail_resize;
static SHORT held_key;
static DWORD (__stdcall *pump)(void);
static DWORD (__stdcall *decide)(int,DWORD,DWORD);
static BYTE* view;

static HMODULE WINAPI mock_module(LPCWSTR name){(void)name;return (HMODULE)image;}
static DWORD WINAPI mock_owner(HWND hwnd,LPDWORD owner){(void)hwnd;*owner=GetCurrentProcessId();return GetCurrentThreadId();}
static HWND WINAPI mock_foreground(void){return foreground?(HWND)1:(HWND)2;}
static SHORT WINAPI mock_key(int key){return key==held_key?-32768:0;}
static HHOOK WINAPI mock_hook(int kind,HOOKPROC procedure,HINSTANCE instance,DWORD thread){
    (void)instance;
    if(kind!=WH_GETMESSAGE || thread!=GetCurrentThreadId())return NULL;
    ++installs;callback=procedure;return (HHOOK)1;
}
static LRESULT WINAPI mock_next(HHOOK hook,int code,WPARAM remove,LPARAM message){
    (void)hook;(void)code;(void)remove;(void)message;++next_calls;return 77;
}

static SHORT __cdecl fake_resize(int width,int height,int colors,int flags){
    ++resizes;
    if(colors!=0x100 || flags!=1 || (width!=960 && width!=1920) || height*16!=width*9)return 0;
    if(fail_resize)return 0;
    *(WORD*)(image+0x1508fc)=(WORD)width;*(WORD*)(image+0x1508fe)=(WORD)height;
    *(SHORT*)(view+0x4c)=(SHORT)width;*(SHORT*)(view+0x4e)=(SHORT)height;
    return 1;
}
static void __fastcall fake_zoom(void* object,void* unused,int direction){
    (void)unused;++zooms;
    if(object!=view || direction!=0)return;
    *(WORD*)(view+0x5e)=0;
    *(SHORT*)(view+0x4c)/=2;*(SHORT*)(view+0x4e)/=2;
}
static void __fastcall fake_clamp(void* object,void* unused){
    (void)unused;if(object==view)++clamps;
}

static BOOL patch_import(HMODULE module,const char* name,ULONG_PTR target){
    BYTE* base=(BYTE*)module;IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS32* nt=(IMAGE_NT_HEADERS32*)(base+dos->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR* desc=(IMAGE_IMPORT_DESCRIPTOR*)(base+nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for(;desc->Name;++desc){
        IMAGE_THUNK_DATA32* lookup=(IMAGE_THUNK_DATA32*)(base+desc->OriginalFirstThunk);
        IMAGE_THUNK_DATA32* iat=(IMAGE_THUNK_DATA32*)(base+desc->FirstThunk);
        for(;lookup->u1.AddressOfData;++lookup,++iat){
            if(!(lookup->u1.Ordinal&IMAGE_ORDINAL_FLAG32)){
                IMAGE_IMPORT_BY_NAME* entry=(IMAGE_IMPORT_BY_NAME*)(base+lookup->u1.AddressOfData);
                if(!strcmp((const char*)entry->Name,name)){
                    DWORD protection;
                    if(!VirtualProtect(&iat->u1.Function,sizeof(DWORD),PAGE_READWRITE,&protection))return FALSE;
                    iat->u1.Function=(DWORD)target;
                    VirtualProtect(&iat->u1.Function,sizeof(DWORD),protection,&protection);return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static void trampoline(DWORD rva,const BYTE* prefix,UINT length,ULONG_PTR function){
    BYTE* out=image+rva;CopyMemory(out,prefix,length);out+=length;
    *out++=0xb8;CopyMemory(out,&function,4);out+=4;*out++=0xff;*out=0xe0;
}

static void setup_image(void){
    IMAGE_DOS_HEADER* dos;IMAGE_NT_HEADERS32* nt;
    const BYTE resize_prefix[]={0x51,0x57,0xe8,0,0,0,0,0x5a,0x5f,0x59};
    const BYTE zoom_prefix[]={0x66,0x83,0x7c,0x24,0x04,0x00,0x53,0x55,0x5d,0x5b};
    image=VirtualAlloc(NULL,0x200000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    dos=(IMAGE_DOS_HEADER*)image;dos->e_magic=IMAGE_DOS_SIGNATURE;dos->e_lfanew=0x100;
    nt=(IMAGE_NT_HEADERS32*)(image+0x100);nt->Signature=IMAGE_NT_SIGNATURE;
    nt->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR32_MAGIC;nt->OptionalHeader.SizeOfImage=0x200000;
    view=image+0x167ef8;
    *(BYTE**)(image+0x15aea8)=view;*(SHORT*)(image+0x11bee8)=0;
    *(ULONG_PTR*)view=(ULONG_PTR)(image+0x107534);
    *(ULONG_PTR*)(image+0x179260)=1;*(HWND*)(image+0x179290)=(HWND)1;
    *(WORD*)(image+0x1508fc)=1920;*(WORD*)(image+0x1508fe)=1080;
    *(SHORT*)(view+0x4c)=1920;*(SHORT*)(view+0x4e)=1080;
    *(SHORT*)(view+0x38)=300;*(SHORT*)(view+0x3a)=400;
    trampoline(0x6fa80,resize_prefix,sizeof(resize_prefix),(ULONG_PTR)fake_resize);
    trampoline(0x7d430,zoom_prefix,sizeof(zoom_prefix),(ULONG_PTR)fake_zoom);
    trampoline(0x7d340,NULL,0,(ULONG_PTR)fake_clamp);
    FlushInstructionCache(GetCurrentProcess(),image,0x200000);
}

static MSG event(int delta){
    MSG message={0};message.hwnd=(HWND)1;message.message=WM_MOUSEWHEEL;
    message.wParam=MAKEWPARAM(0,(WORD)(SHORT)delta);return message;
}
#define CHECK(c) do{if(!(c)){printf("failure_line=%d\n",__LINE__);return 1;}++checks;}while(0)

int main(int argc,char** argv){
    HMODULE module;MSG message;UINT checks=0,index;SHORT center_x,center_y;
    if(argc!=2)return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    setup_image();CHECK(image!=NULL);
    module=LoadLibraryA(argv[1]);CHECK(module!=NULL);
    CHECK(patch_import(module,"GetModuleHandleW",(ULONG_PTR)mock_module));
    CHECK(patch_import(module,"GetWindowThreadProcessId",(ULONG_PTR)mock_owner));
    CHECK(patch_import(module,"GetForegroundWindow",(ULONG_PTR)mock_foreground));
    CHECK(patch_import(module,"GetAsyncKeyState",(ULONG_PTR)mock_key));
    CHECK(patch_import(module,"SetWindowsHookExW",(ULONG_PTR)mock_hook));
    CHECK(patch_import(module,"CallNextHookEx",(ULONG_PTR)mock_next));
    pump=(DWORD (__stdcall *)(void))GetProcAddress(module,"WBZoomPump");
    decide=(DWORD (__stdcall *)(int,DWORD,DWORD))GetProcAddress(module,"WBZoomDecision");
    CHECK(pump!=NULL && decide!=NULL);CHECK(pump()==1 && installs==1 && callback!=NULL);
    CHECK(pump()==1 && installs==1);
    message=event(120);callback(HC_ACTION,PM_NOREMOVE,(LPARAM)&message);
    CHECK(resizes==0 && message.message==WM_MOUSEWHEEL);
    callback(-1,PM_REMOVE,(LPARAM)&message);CHECK(resizes==0);
    foreground=FALSE;callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);
    CHECK(resizes==0 && message.message==WM_MOUSEWHEEL);foreground=TRUE;
    for(index=0;index<5;++index){
        const SHORT keys[]={VK_LBUTTON,VK_RBUTTON,VK_CONTROL,VK_MENU,VK_SHIFT};
        held_key=keys[index];message=event(120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);
        CHECK(resizes==0 && message.message==WM_MOUSEWHEEL);
    }
    held_key=0;
    *(BYTE**)(view+0x400)=image+0x180000;*(WORD*)(image+0x180018)=1;
    message=event(120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);CHECK(resizes==0);
    *(BYTE**)(view+0x400)=NULL;
    *(SHORT*)(image+0x11bee8)=1;*(BYTE**)(image+0x15aeac)=image+0x181000;
    message=event(120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);CHECK(resizes==0);
    *(SHORT*)(image+0x11bee8)=0;
    center_x=*(SHORT*)(view+0x38)+*(SHORT*)(view+0x4c)/2;
    center_y=*(SHORT*)(view+0x3a)+*(SHORT*)(view+0x4e)/2;
    for(index=0;index<4;++index){
        message=event(30);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);
        CHECK(resizes==(index==3?1U:0U));
    }
    CHECK(message.message==WM_NULL && *(WORD*)(image+0x1508fc)==960 && *(WORD*)(image+0x1508fe)==540);
    CHECK(*(SHORT*)(view+0x38)+*(SHORT*)(view+0x4c)/2==center_x);
    CHECK(*(SHORT*)(view+0x3a)+*(SHORT*)(view+0x4e)/2==center_y && clamps==1);
    message=event(360);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);CHECK(resizes==1);
    message=event(-120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);
    CHECK(resizes==2 && message.message==WM_NULL && *(WORD*)(image+0x1508fc)==1920);
    CHECK(*(SHORT*)(view+0x38)==300 && *(SHORT*)(view+0x3a)==400);
    fail_resize=TRUE;message=event(120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);
    CHECK(resizes==3 && message.message==WM_MOUSEWHEEL && *(WORD*)(image+0x1508fc)==1920);
    fail_resize=FALSE;
    message=event(120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);CHECK(resizes==4);
    *(WORD*)(view+0x5e)=1;*(SHORT*)(view+0x4c)=1920;*(SHORT*)(view+0x4e)=1080;
    message=event(-120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);
    CHECK(resizes==5 && zooms==1 && *(WORD*)(view+0x5e)==0);
    message=event(120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);CHECK(resizes==6);
    *(SHORT*)(image+0x11bee8)=1;
    ZeroMemory(&message,sizeof(message));message.message=WM_MOUSEMOVE;message.hwnd=(HWND)1;
    callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);
    CHECK(resizes==7 && *(WORD*)(image+0x1508fc)==1920);
    CHECK(message.message==WM_MOUSEMOVE);
    callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);CHECK(resizes==7);
    *(SHORT*)(image+0x11bee8)=0;
    message=event(120);callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);CHECK(resizes==8);
    message.message=WM_CLOSE;callback(HC_ACTION,PM_REMOVE,(LPARAM)&message);
    CHECK(resizes==9 && *(WORD*)(image+0x1508fc)==1920 && message.message==WM_CLOSE);
    CHECK(next_calls>20);
    printf("production_input_checks=%u bootstrap=ok queued_wheel=ok resize_ABI=ok center=ok context=ok game_not_started=1\n",checks);
    return 0;
}
