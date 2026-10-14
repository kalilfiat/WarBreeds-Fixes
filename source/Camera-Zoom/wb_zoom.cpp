#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <windowsx.h>
#include <stdio.h>

static HINSTANCE instance;
static INIT_ONCE once=INIT_ONCE_STATIC_INIT;
static BOOL enabled=TRUE, invert=FALSE, processing=FALSE;
static BOOL resolution_zoom=TRUE, close_owned=FALSE;
static int remainder;
static HHOOK message_hook;
static BYTE* game;
static HWND game_window;
static ULONGLONG retry_at;
static WCHAR log_path[MAX_PATH];
static UINT logged_events;
static DWORD rejected;

static void log_event(const char* message){
    if(!log_path[0])return;
    HANDLE file=CreateFileW(log_path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,
                            NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file!=INVALID_HANDLE_VALUE){
        DWORD written;
        if(GetFileSize(file,NULL)<65536){WriteFile(file,message,(DWORD)strlen(message),&written,NULL);}
        CloseHandle(file);
    }
}

static BOOL CALLBACK initialize(PINIT_ONCE init,PVOID arg,PVOID*ctx){
    WCHAR path[MAX_PATH],*name;
    const WCHAR filename[]=L"WarBreeds-Zoom.ini";
    DWORD length=GetModuleFileNameW(instance,path,MAX_PATH);
    (void)init;(void)arg;(void)ctx;
    if(length && length<MAX_PATH){
        name=path+length;
        while(name>path && name[-1]!=L'\\' && name[-1]!=L'/')--name;
        if((UINT)(name-path)+sizeof(filename)/sizeof(WCHAR)<=MAX_PATH){
            CopyMemory(name,filename,sizeof(filename));
            enabled=GetPrivateProfileIntW(L"Zoom",L"Enabled",1,path)!=0;
            invert=GetPrivateProfileIntW(L"Zoom",L"InvertWheel",0,path)!=0;
            resolution_zoom=GetPrivateProfileIntW(L"Zoom",L"ResolutionZoom",1,path)!=0;
            const WCHAR log_name[]=L"MODS\\Camera-Zoom\\runtime.log";
            if((UINT)(name-path)+sizeof(log_name)/sizeof(WCHAR)<=MAX_PATH){
                CopyMemory(name,log_name,sizeof(log_name));
                CopyMemory(log_path,path,(wcslen(path)+1)*sizeof(WCHAR));
            }
        }
    }
    return TRUE;
}

/* Pure wheel decision shared by the real mouse hook and native isolated tests.
   Native zoom has TWO scales: never apply the same scale a second time. */
extern "C" DWORD __stdcall WBZoomDecision(int delta,DWORD mode,DWORD accepts_input){
    InitOnceExecuteOnce(&once,initialize,NULL,NULL);
    if(!enabled || !accepts_input || mode>1){remainder=0;return 0xffffffff;}
    if(invert)delta=-delta;
    // A real Windows wheel delta is a signed 16-bit value.
    if(delta < -32768 || delta > 32768){remainder=0;return 0xffffffff;}
    remainder+=delta;
    if(remainder>=WHEEL_DELTA){remainder%=WHEEL_DELTA;return mode==1?0UL:0xffffffff;}
    if(remainder<=-WHEEL_DELTA){remainder%=WHEEL_DELTA;return mode==0?1UL:0xffffffff;}
    return 0xffffffff;
}

static BOOL active_game(){
    // Static SGame lives for the process lifetime. Only its topmost active scene
    // may receive wheel zoom; no remembered heap view or delayed commands.
    BYTE* view=game+0x167ef8;
    SHORT depth=*(SHORT*)(game+0x11bee8);
    if(depth<0 || depth>3){rejected=1;return FALSE;}
    if(*(BYTE**)(game+0x15aea8+depth*4)!=view){rejected=2;return FALSE;}
    if(*(ULONG_PTR*)view!=(ULONG_PTR)(game+0x107534)){rejected=3;return FALSE;}
    if(!*(ULONG_PTR*)(game+0x179260)){rejected=4;return FALSE;}
    rejected=0;return TRUE;
}

static BOOL accepts_wheel(const MSG* message){
    BYTE* view=game+0x167ef8;
    if(!active_game())return FALSE;
    if(message->hwnd!=game_window){rejected=5;return FALSE;}
    if(GetForegroundWindow()!=game_window){rejected=6;return FALSE;}
    if(GetAsyncKeyState(VK_LBUTTON)&0x8000 || GetAsyncKeyState(VK_RBUTTON)&0x8000 ||
       GetAsyncKeyState(VK_CONTROL)&0x8000 || GetAsyncKeyState(VK_MENU)&0x8000 ||
       GetAsyncKeyState(VK_SHIFT)&0x8000){rejected=7;return FALSE;}
    // The original keyboard handler tests these two text widgets for command/chat.
    BYTE* command=*(BYTE**)(view+0x41c);BYTE* chat=*(BYTE**)(view+0x400);
    if(command && *(WORD*)(command+0x18)==1){rejected=8;return FALSE;}
    if(chat && *(WORD*)(chat+0x18)==1){rejected=9;return FALSE;}
    return TRUE;
}

static BOOL change_resolution(DWORD direction){
    typedef SHORT (__cdecl *Resize)(int,int,int,int);
    typedef void (__thiscall *Zoom)(void*,int);
    typedef void (__thiscall *Clamp)(void*);
    BYTE* view=game+0x167ef8;
    int width=direction==0?960:1920, height=direction==0?540:1080;
    int old_width=*(WORD*)(game+0x1508fc),old_height=*(WORD*)(game+0x1508fe);
    if(old_width==width && old_height==height && *(WORD*)(view+0x5e)==0)return TRUE;
    int center_x=*(SHORT*)(view+0x38)+*(SHORT*)(view+0x4c)/2;
    int center_y=*(SHORT*)(view+0x3a)+*(SHORT*)(view+0x4e)/2;
    WORD old_native_mode=*(WORD*)(view+0x5e);
    if(old_native_mode==1)((Zoom)(game+0x7d430))(view,0);
    SHORT result=((Resize)(game+0x6fa80))(width,height,0x100,1);
    BOOL changed=result==1 && *(WORD*)(game+0x1508fc)==width && *(WORD*)(game+0x1508fe)==height;
    if(changed){
        if(active_game()){
            *(SHORT*)(view+0x38)=(SHORT)(center_x-*(SHORT*)(view+0x4c)/2);
            *(SHORT*)(view+0x3a)=(SHORT)(center_y-*(SHORT*)(view+0x4e)/2);
            ((Clamp)(game+0x7d340))(view);
        }
        close_owned=direction==0;
    }else if(old_native_mode==1 && active_game()){
        ((Zoom)(game+0x7d430))(view,1);
    }
    char line[160];
    sprintf_s(line,"resolution %dx%d -> %dx%d result=%d actual=%ux%u success=%u\r\n",
              old_width,old_height,width,height,result,*(WORD*)(game+0x1508fc),
              *(WORD*)(game+0x1508fe),(UINT)changed);
    log_event(line);
    return changed;
}

static LRESULT CALLBACK message_proc(int code,WPARAM remove,LPARAM data){
    if(code==HC_ACTION && remove==PM_REMOVE && game && !processing){
        MSG* message=(MSG*)data;
        if(resolution_zoom && close_owned &&
           (!active_game() || message->message==WM_CLOSE || message->message==WM_QUIT)){
            // Restore between messages, never from the drawing bootstrap. Do not
            // call the scene dispatcher once it has destroyed the scene stack.
            SHORT depth=*(SHORT*)(game+0x11bee8);
            if(depth>=0 && depth<=3 && *(BYTE**)(game+0x15aea8)==game+0x167ef8 &&
               *(WORD*)(game+0x1508fc)==960 &&
               *(WORD*)(game+0x1508fe)==540){
                processing=TRUE;change_resolution(1);processing=FALSE;
            }
            close_owned=FALSE;
        }
        if(message->message==WM_MOUSEWHEEL){
            BYTE* view=game+0x167ef8;
            BOOL accepts=accepts_wheel(message);
            WORD width=*(WORD*)(game+0x1508fc),height=*(WORD*)(game+0x1508fe);
            DWORD mode=resolution_zoom?((width<=960 && height<=540)?0UL:1UL):*(WORD*)(view+0x5e);
            int delta=GET_WHEEL_DELTA_WPARAM(message->wParam);
            DWORD decision=WBZoomDecision(delta,mode,accepts);
            if(logged_events++<32){
                char line[160];sprintf_s(line,"wheel delta=%d accepts=%u reason=%lu resolution=%ux%u native=%u decision=%lu\r\n",
                                         delta,(UINT)accepts,rejected,width,height,*(WORD*)(view+0x5e),decision);
                log_event(line);
            }
            if(decision!=0xffffffff){
                typedef void (__thiscall *Zoom)(void*,int);
                processing=TRUE;
                BOOL handled=TRUE;
                if(resolution_zoom)handled=change_resolution(decision);
                else ((Zoom)(game+0x7d430))(view,(int)decision);
                processing=FALSE;
                if(handled){message->message=WM_NULL;message->wParam=0;message->lParam=0;}
            }
        }
    }
    return CallNextHookEx(message_hook,code,remove,data);
}

extern "C" DWORD __stdcall WBZoomPump(void){
    BYTE* module;IMAGE_DOS_HEADER* dos;IMAGE_NT_HEADERS32* nt;
    DWORD owner;DWORD thread;
    const BYTE signature[]={0x66,0x83,0x7c,0x24,0x04,0x00,0x53,0x55};
    InitOnceExecuteOnce(&once,initialize,NULL,NULL);
    if(!enabled)return 0;
    if(message_hook)return 1;
    if(GetTickCount64()<retry_at)return 0;
    retry_at=GetTickCount64()+1000;
    module=(BYTE*)GetModuleHandleW(NULL);dos=(IMAGE_DOS_HEADER*)module;
    if(!module || dos->e_magic!=IMAGE_DOS_SIGNATURE)return 0;
    nt=(IMAGE_NT_HEADERS32*)(module+dos->e_lfanew);
    const BYTE resize_signature[]={0x51,0x57,0xe8};
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
       nt->OptionalHeader.SizeOfImage<0x179294 || memcmp(module+0x7d430,signature,sizeof(signature)) ||
       memcmp(module+0x6fa80,resize_signature,sizeof(resize_signature)))return 0;
    game_window=*(HWND*)(module+0x179290);
    if(!game_window)return 0;
    thread=GetWindowThreadProcessId(game_window,&owner);
    if(!thread || owner!=GetCurrentProcessId())return 0;
    game=module;
    // Read the real dequeued WM_MOUSEWHEEL. PM_NOREMOVE must not apply a zoom
    // twice. This is thread-specific and retains DDrawCompat's upstream capture.
    message_hook=SetWindowsHookExW(WH_GETMESSAGE,message_proc,instance,thread);
    char line[120];sprintf_s(line,"WBZoom v2 hook=%u error=%lu resolutionZoom=%u\r\n",
                            (UINT)(message_hook!=NULL),message_hook?0:GetLastError(),(UINT)resolution_zoom);
    log_event(line);
    return message_hook!=NULL;
}

BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH)instance=module;
    // The EXE imports this DLL for its lifetime; Windows removes the thread hook
    // on thread/process exit. No hook installation or unhooking under loader lock.
    return TRUE;
}
