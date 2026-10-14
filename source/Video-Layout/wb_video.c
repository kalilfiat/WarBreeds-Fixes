/* WarBreeds: proportional QuickTime movie box, before controller creation. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>

typedef struct { SHORT left,top,right,bottom; } VideoRect;
static HINSTANCE instance;
static INIT_ONCE once=INIT_ONCE_STATIC_INIT;
static BOOL enabled=TRUE;
static DWORD canvas_width=3840,canvas_height=2160;
static WCHAR log_path[MAX_PATH];
typedef struct {BYTE* scene;WORD w,h,scene_w,scene_h,flags;DWORD colors;} PreviousMode;
static PreviousMode previous[4];

static BOOL CALLBACK initialize(PINIT_ONCE init,PVOID arg,PVOID* context){
    WCHAR path[MAX_PATH],*name;
    DWORD length=GetModuleFileNameW(instance,path,MAX_PATH);
    const WCHAR ini[]=L"WarBreeds-Video.ini";
    const WCHAR log[]=L"MODS\\Video-Layout\\runtime.log";
    (void)init;(void)arg;(void)context;
    if(length && length<MAX_PATH){
        name=path+length;
        while(name>path && name[-1]!=L'\\' && name[-1]!=L'/')--name;
        if((UINT)(name-path)+sizeof(ini)/sizeof(WCHAR)<=MAX_PATH){
            CopyMemory(name,ini,sizeof(ini));
            enabled=GetPrivateProfileIntW(L"Video",L"Enabled",1,path)!=0;
            canvas_width=GetPrivateProfileIntW(L"Video",L"CanvasWidth",3840,path);
            canvas_height=GetPrivateProfileIntW(L"Video",L"CanvasHeight",2160,path);
            if(canvas_width<640 || canvas_width>4096 || canvas_height<480 || canvas_height>4096){canvas_width=3840;canvas_height=2160;}
        }
        if((UINT)(name-path)+sizeof(log)/sizeof(WCHAR)<=MAX_PATH){
            CopyMemory(name,log,sizeof(log));CopyMemory(log_path,path,(wcslen(path)+1)*sizeof(WCHAR));
        }
    }
    return TRUE;
}

static void log_result(UINT w,UINT h,UINT cw,UINT ch,const VideoRect* r,BOOL ok,SHORT error){
    char line[160];HANDLE file;DWORD written;
    if(!log_path[0])return;
    sprintf_s(line,sizeof(line),"movie %ux%u canvas=%ux%u rect=%d,%d,%d,%d QuickTimeBox=%u error=%d\r\n",
              w,h,cw,ch,r->left,r->top,r->right,r->bottom,(UINT)ok,error);
    file=CreateFileW(log_path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,
                     OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file!=INVALID_HANDLE_VALUE){
        if(GetFileSize(file,NULL)<65536)WriteFile(file,line,(DWORD)strlen(line),&written,NULL);
        CloseHandle(file);
    }
}

DWORD __stdcall WBVideoRect(DWORD w,DWORD h,DWORD cw,DWORD ch,VideoRect* result){
    DWORD width,height,left,top;
    if(!result || !w || !h || !cw || !ch || w>8192 || h>8192 || cw>8192 || ch>8192)return 0;
    width=cw;height=(DWORD)(((ULONGLONG)h*cw)/w);
    if(height>ch){height=ch;width=(DWORD)(((ULONGLONG)w*ch)/h);}
    width&=~3UL;height&=~3UL;
    if(!width || !height)return 0;
    left=((cw-width)/2)&~3UL;top=((ch-height)/2)&~3UL;
    result->left=(SHORT)left;result->top=(SHORT)top;
    result->right=(SHORT)(left+width);result->bottom=(SHORT)(top+height);
    return 1;
}

DWORD __stdcall WBVideoFit(void* object,const WORD* dimensions,VideoRect* result){
    BYTE* scene=(BYTE*)object;
    DWORD w,h,cw,ch;
    InitOnceExecuteOnce(&once,initialize,NULL,NULL);
    if(!enabled || !scene || !dimensions || !result)return 0;
    w=dimensions[0];h=dimensions[1];cw=*(WORD*)(scene+0x28);ch=*(WORD*)(scene+0x2a);
    return WBVideoRect(w,h,cw,ch,result);
}

DWORD __stdcall WBVideoCanvas(void* object){
    typedef SHORT (__cdecl *Resize)(int,int,int,int);
    BYTE* scene=(BYTE*)object;BYTE* module=(BYTE*)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)module;IMAGE_NT_HEADERS32* nt;
    SHORT depth,result;char line[160];HANDLE file;DWORD written;PreviousMode* saved;BYTE* root;
    const BYTE signature[]={0x51,0x57,0xe8};
    InitOnceExecuteOnce(&once,initialize,NULL,NULL);
    if(!enabled || !scene || !module || dos->e_magic!=IMAGE_DOS_SIGNATURE)return 0;
    nt=(IMAGE_NT_HEADERS32*)(module+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
       nt->OptionalHeader.SizeOfImage<0x179294 || memcmp(module+0x6fa80,signature,sizeof(signature)))return 0;
    depth=*(SHORT*)(module+0x11bee8);
    if(depth<0 || depth>3 || *(BYTE**)(module+0x15aea8+depth*4)!=scene || !*(HWND*)(module+0x179290))return 0;
    saved=&previous[depth];root=*(BYTE**)(module+0x15aea8);
    if(saved->scene)return 0;
    saved->w=*(WORD*)(module+0x1508fc);saved->h=*(WORD*)(module+0x1508fe);
    saved->scene_w=*(WORD*)(scene+0x28);saved->scene_h=*(WORD*)(scene+0x2a);
    saved->colors=root==scene?*(DWORD*)(module+0x1509c4):*(DWORD*)(root+0x2c);
    saved->flags=root==scene?1:*(WORD*)(root+0x30);
    if(!saved->colors)saved->colors=256;
    // Movie playback blocks inside scene initialization, BEFORE the usual scene
    // dispatcher switches mode. Change it after the movie's desktop reset and
    // before constructing its QuickTime controller, using the native dispatcher.
    result=((Resize)(module+0x6fa80))((int)canvas_width,(int)canvas_height,*(int*)(scene+0x2c),*(WORD*)(scene+0x30));
    if(result==1 && *(WORD*)(module+0x1508fc)==canvas_width && *(WORD*)(module+0x1508fe)==canvas_height){
        saved->scene=scene;
        *(WORD*)(scene+0x28)=(WORD)canvas_width;*(WORD*)(scene+0x2a)=(WORD)canvas_height;
    }else result=0;
    sprintf_s(line,sizeof(line),"canvas result=%d actual=%ux%u scene=%ux%u\r\n",result,
              *(WORD*)(module+0x1508fc),*(WORD*)(module+0x1508fe),*(WORD*)(scene+0x28),*(WORD*)(scene+0x2a));
    if(log_path[0]){
        file=CreateFileW(log_path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(file!=INVALID_HANDLE_VALUE){
            if(GetFileSize(file,NULL)<65536)WriteFile(file,line,(DWORD)strlen(line),&written,NULL);
            CloseHandle(file);
        }
    }
    return result==1;
}

DWORD __stdcall WBVideoRestore(void* object){
    typedef SHORT (__cdecl *Resize)(int,int,int,int);
    BYTE* module=(BYTE*)GetModuleHandleW(NULL);BYTE* scene=(BYTE*)object;
    UINT index;SHORT depth,result=0;PreviousMode saved;
    if(!module || !scene)return 0;
    for(index=0;index<4 && previous[index].scene!=scene;++index){}
    if(index==4)return 0;
    saved=previous[index];previous[index].scene=NULL;
    depth=*(SHORT*)(module+0x11bee8);
    if(depth>=0 && depth<=3 && *(BYTE**)(module+0x15aea8+index*4)==scene){
        result=((Resize)(module+0x6fa80))(saved.w,saved.h,(int)saved.colors,saved.flags);
        *(WORD*)(scene+0x28)=saved.scene_w;*(WORD*)(scene+0x2a)=saved.scene_h;
    }
    return result==1;
}

DWORD __stdcall WBVideoScale(void* object){
    typedef void (__cdecl *MovieBox)(void*,RECT*);
    typedef SHORT (__cdecl *MovieError)(void);
    BYTE* scene=(BYTE*)object;BYTE* module;BYTE* player;BYTE* movie;
    IMAGE_DOS_HEADER* dos;IMAGE_NT_HEADERS32* nt;
    RECT original,scaled,actual;VideoRect fit;
    DWORD w,h,cw,ch;BOOL accepted;SHORT error;
    const BYTE get_signature[]={0x53,0x66,0xbb,0x0f,0x00,0xff,0x15};
    const BYTE set_signature[]={0x53,0x66,0xbb,0x32,0x00,0xff,0x15};
    const BYTE error_signature[]={0x53,0x66,0xbb,0x0d,0x00,0xff,0x15};
    InitOnceExecuteOnce(&once,initialize,NULL,NULL);
    if(!enabled || !scene)return 0;
    player=*(BYTE**)(scene+0x38);
    if(!player || !(movie=*(BYTE**)(player+4)) || *(DWORD*)movie!=0x49564f4d || !*(ULONG_PTR*)(movie+0x10))return 0;
    w=*(WORD*)(movie+0x14);h=*(WORD*)(movie+0x16);
    cw=*(WORD*)(scene+0x28);ch=*(WORD*)(scene+0x2a);
    fit=*(VideoRect*)(player+8);
    if(!w || !h || fit.left<0 || fit.top<0 || fit.right>(LONG)cw || fit.bottom>(LONG)ch ||
       fit.right<=fit.left || fit.bottom<=fit.top)return 0;
    module=(BYTE*)GetModuleHandleW(NULL);dos=(IMAGE_DOS_HEADER*)module;
    if(!module || dos->e_magic!=IMAGE_DOS_SIGNATURE)return 0;
    nt=(IMAGE_NT_HEADERS32*)(module+dos->e_lfanew);
    if(nt->Signature!=IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
       nt->OptionalHeader.SizeOfImage<0x120f10 || memcmp(module+0xeaf2d,get_signature,sizeof(get_signature)) ||
       memcmp(module+0xeb0f4,set_signature,sizeof(set_signature)) || memcmp(module+0xeaf13,error_signature,sizeof(error_signature)) ||
       !*(ULONG_PTR*)(module+0x120f0c))return 0;
    ((MovieError)(module+0xeaf13))();
    ((MovieBox)(module+0xeaf2d))(*(void**)(movie+0x10),&original);
    scaled.left=fit.left;scaled.top=fit.top;scaled.right=fit.right;scaled.bottom=fit.bottom;
    ((MovieBox)(module+0xeb0f4))(*(void**)(movie+0x10),&scaled);
    error=((MovieError)(module+0xeaf13))();
    ((MovieBox)(module+0xeaf2d))(*(void**)(movie+0x10),&actual);
    accepted=error==0 && EqualRect(&actual,&scaled);
    if(!accepted)((MovieBox)(module+0xeb0f4))(*(void**)(movie+0x10),&original);
    log_result(w,h,cw,ch,&fit,accepted,error);
    return accepted;
}

BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH)instance=module;
    return TRUE;
}
