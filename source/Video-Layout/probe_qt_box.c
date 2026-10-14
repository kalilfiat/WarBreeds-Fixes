/* Real QuickTime 2 file import and box scaling. No playback or window. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
static FARPROC qt_entry;
#pragma warning(push)
#pragma warning(disable:4100) /* Naked entry thunks forward caller arguments on the stack. */
__declspec(naked) int enter_movies(void){__asm push ebx __asm mov bx,0x0b __asm call qt_entry __asm pop ebx __asm ret}
__declspec(naked) void exit_movies(void){__asm push ebx __asm mov bx,0x0c __asm call qt_entry __asm pop ebx __asm ret}
__declspec(naked) int new_movie(void** movie,HFILE file,int reserved,int flags){__asm push ebx __asm mov bx,0x29 __asm call qt_entry __asm pop ebx __asm ret}
__declspec(naked) void get_box(void* movie,RECT* box){__asm push ebx __asm mov bx,0x0f __asm call qt_entry __asm pop ebx __asm ret}
__declspec(naked) void set_box(void* movie,RECT* box){__asm push ebx __asm mov bx,0x32 __asm call qt_entry __asm pop ebx __asm ret}
#pragma warning(pop)

int main(int argc,char** argv){
    HMODULE qt,manager;FARPROC init;HFILE file;void* movie=NULL;
    RECT box={0},target={0},after={0};int error;
    if(argc!=5)return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    SetDllDirectoryA(argv[1]);qt=LoadLibraryA("qtim32.dll");manager=LoadLibraryA("cmgr32.dll");
    if(!qt || !manager)return 3;
    qt_entry=GetProcAddress(qt,"_EntryPoint");init=GetProcAddress(manager,"_CMgrInitialize");
    if(!qt_entry || !init)return 4;
    if(((int (__cdecl*)(void))init)()!=0 || enter_movies()!=0)return 5;
    file=_lopen(argv[2],OF_READ);if(file==HFILE_ERROR)return 6;
    error=(SHORT)new_movie(&movie,file,0,0);printf("import_error=%d movie_present=%u\n",error,(UINT)(movie!=NULL));fflush(stdout);
    if(error || !movie){_lclose(file);exit_movies();return 7;}
    get_box(movie,&box);printf("original_box=%ld,%ld,%ld,%ld\n",box.left,box.top,box.right,box.bottom);fflush(stdout);
    target.right=atoi(argv[3]);target.bottom=atoi(argv[4]);set_box(movie,&target);get_box(movie,&after);
    printf("scaled_box=%ld,%ld,%ld,%ld expected=%ldx%ld game_not_started=1 playback=0\n",
           after.left,after.top,after.right,after.bottom,target.right,target.bottom);fflush(stdout);
    error=after.right-after.left!=target.right || after.bottom-after.top!=target.bottom;
    set_box(movie,&box);_lclose(file);exit_movies();return error?8:0;
}
