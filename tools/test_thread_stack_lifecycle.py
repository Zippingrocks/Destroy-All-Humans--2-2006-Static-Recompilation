"""Native regression for actual kernel stack allocation and thread lifecycle.

The C harness extracts the repaired production bodies and uses real Windows
threads/events. Only allocation/thread creation failure injection and dispatch
lookup are test doubles. No game process is launched or modified.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
bridge = (ROOT / 'xboxrecomp/src/kernel/kernel_bridge.c').read_text(encoding='utf-8')
layout = (ROOT / 'xboxrecomp/src/kernel/xbox_memory_layout.c').read_text(encoding='utf-8')
header = (ROOT / 'xboxrecomp/src/kernel/xbox_memory_layout.h').read_text(encoding='utf-8')

def function(source, name):
    match = re.search(r'^(?:static )?(?:void|uint32_t|DWORD WINAPI|HANDLE) ' + name + r'\([^;]*?\)\n\{.*?^\}', source, re.M | re.S)
    if not match:
        match = re.search(r'^void ' + name + r'\([^;]*?\) \{[^\n]*\}', source, re.M)
    assert match, name
    return match.group()

assert 'void xbox_FreeThreadStack(uint32_t stack_top);' in header
assert 'running worker' not in function(bridge, 'bridge_PsCreateSystemThreadEx')
terminate = function(bridge, 'bridge_PsTerminateSystemThread')
assert re.search(r'bridge_release_thread_stack\(\);\s*ExitThread\(exit_status\);', terminate)
prefix = r'''
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(v) do {if(!(v)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v);ExitProcess(3);}}while(0)
#define RECOMP_TLS __declspec(thread)
#define XBOX_STACK_BASE 0x00780000u
#define XBOX_THREAD_STACK_SIZE (512*1024)
#define XBOX_MAX_THREAD_STACKS 8
#define XBOX_THREAD_MODE_INLINE 0
#define XBOX_THREAD_MODE_SPAWN 1
static int g_thread_stacks_used,g_thread_call_count;
static volatile LONG g_thread_stack_slots[XBOX_MAX_THREAD_STACKS];
static RECOMP_TLS int g_is_spawned_thread;
static RECOMP_TLS uint32_t g_spawned_stack_top;
static RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi,g_ebp,g_seh_ebp;
static ptrdiff_t g_xbox_mem_offset;
static unsigned char *memory;
static unsigned char failure_snapshot[0x1000000];
typedef void (*recomp_func_t)(void);
static void normal_worker(void),terminate_worker(void),blocking_worker(void),inline_worker(void);
static recomp_func_t recomp_lookup(uint32_t va) {
    switch(va){case 1:return normal_worker;case 2:return terminate_worker;
        case 3:return blocking_worker;case 4:return inline_worker;default:return NULL;}
}
static recomp_func_t recomp_lookup_manual(uint32_t va){(void)va;return NULL;}
static uint32_t *checked_mem32(uint32_t va) {
    CHECK(va+4u<0x1000000u);
    /* A freed slice must never be touched by its previous owner. */
    CHECK(!g_is_spawned_thread || g_spawned_stack_top!=0);
    return (uint32_t *)(memory+va);
}
#define BRIDGE_MEM32(a) (*checked_mem32((uint32_t)(a)))
#define STACK_ARG(n) BRIDGE_MEM32(g_esp+4u*(n))
static volatile LONG fail_malloc,fail_create,workers_entered,terminations;
static volatile LONG startup_allocations;
static DWORD main_tid;
static uint32_t observed_tops[256];
static HANDLE release_event;
static void *test_malloc(size_t size) {
    if(InterlockedExchange(&fail_malloc,0))return NULL;
    void *p=malloc(size);if(p)InterlockedIncrement(&startup_allocations);return p;
}
static void test_free(void *p){if(p)InterlockedDecrement(&startup_allocations);free(p);}
static HANDLE test_CreateThread(LPSECURITY_ATTRIBUTES a,SIZE_T b,LPTHREAD_START_ROUTINE c,LPVOID d,DWORD e,LPDWORD f) {
    if(InterlockedExchange(&fail_create,0)){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}
    return CreateThread(a,b,c,d,e,f);
}
static void test_ExitThread(DWORD status) {
    CHECK(g_is_spawned_thread && !g_spawned_stack_top);
    InterlockedIncrement(&terminations);
    ExitThread(status);
}
static void xbox_set_game_thread(void *h){CHECK(h!=NULL);}
#define malloc test_malloc
#define free test_free
#define CreateThread test_CreateThread
#define ExitThread test_ExitThread
static int g_thread_mode=XBOX_THREAD_MODE_INLINE;
struct bridge_thread_start {recomp_func_t fn;uint32_t ctx1,ctx2,stack_top;};
#define BRIDGE_HANDLE_TAG 0x48000000u
#define BRIDGE_HANDLE_MASK 0x00FFFFFFu
#define BRIDGE_HANDLE_MAX 16384
static HANDLE s_handle_table[BRIDGE_HANDLE_MAX];
static void bridge_write_handle(uint32_t va,HANDLE h);
'''
functions = [function(layout, 'xbox_AllocThreadStack'), function(layout, 'xbox_FreeThreadStack')]
functions += [function(bridge, name) for name in (
    'bridge_release_thread_stack', 'bridge_run_thread_inline', 'bridge_thread_main',
    'bridge_spawn_thread', 'xbox_SetThreadMode', 'bridge_PsCreateSystemThreadEx',
    'bridge_PsTerminateSystemThread')]
functions += [function(bridge, 'bridge_handle_token'), function(bridge, 'bridge_write_handle')]
suffix = r'''
static unsigned cases;
static void check_worker_entry(void) {
    CHECK(GetCurrentThreadId()!=main_tid && g_is_spawned_thread);
    CHECK(g_spawned_stack_top && g_esp==g_spawned_stack_top-12);
    CHECK(BRIDGE_MEM32(g_esp)==0 && BRIDGE_MEM32(g_esp+4)==0x12345678 && BRIDGE_MEM32(g_esp+8)==0x87654321);
    CHECK(g_ecx==0 && g_edx==0 && g_ebx==0 && g_esi==0 && g_edi==0 && g_ebp==0);
    LONG ordinal=InterlockedIncrement(&workers_entered)-1;
    CHECK(ordinal<256);observed_tops[ordinal]=g_spawned_stack_top;
}
static void normal_worker(void){check_worker_entry();g_eax=0x99;}
static void terminate_worker(void){check_worker_entry();g_esp-=4;BRIDGE_MEM32(g_esp)=0x1234;bridge_PsTerminateSystemThread();CHECK(0);}
static void blocking_worker(void){check_worker_entry();CHECK(WaitForSingleObject(release_event,5000)==WAIT_OBJECT_0);}
static void inline_worker(void) {
    CHECK(GetCurrentThreadId()==main_tid && !g_is_spawned_thread && !g_spawned_stack_top);
    CHECK(g_esp==0xF70000-12 && g_ecx==0xAABBCCDD);
    CHECK(BRIDGE_MEM32(g_esp+4)==0x12345678 && BRIDGE_MEM32(g_esp+8)==0x87654321);
    g_eax=0x99;
}
static HANDLE create(unsigned routine,int suspended,int fail) {
    const uint32_t sp=0xF70000,out=0x10000;
    g_eax=0xCD;g_ecx=0xAABBCCDD;g_edx=2;g_ebx=3;g_esi=4;g_edi=5;g_ebp=6;g_esp=sp;
    memset(memory+sp,0xCD,40);BRIDGE_MEM32(out)=0xCDCDCDCD;
    STACK_ARG(0)=out;STACK_ARG(5)=0x12345678;STACK_ARG(6)=0x87654321;
    STACK_ARG(7)=suspended;STACK_ARG(9)=routine;
    uint32_t args_before[10];memcpy(args_before,memory+sp,40);
    if(fail)memcpy(failure_snapshot,memory,0x1000000);
    bridge_PsCreateSystemThreadEx();
    CHECK(g_esp==sp && g_ecx==0xAABBCCDD && g_edx==2 && g_ebx==3 && g_esi==4 && g_edi==5 && g_ebp==6);
    ++cases;
    CHECK(!memcmp(args_before,memory+sp,40));
    if(fail){CHECK(g_eax==0xC000009A && BRIDGE_MEM32(out)==0xCDCDCDCD);CHECK(!memcmp(failure_snapshot,memory,0x1000000));return NULL;}
    CHECK(g_eax==0);
    uint32_t token=BRIDGE_MEM32(out);CHECK((token&0xFF000000)==BRIDGE_HANDLE_TAG);
    CHECK((token&BRIDGE_HANDLE_MASK)>0 && (token&BRIDGE_HANDLE_MASK)<BRIDGE_HANDLE_MAX);
    HANDLE h=s_handle_table[token&BRIDGE_HANDLE_MASK];CHECK(h);return h;
}
static void join(HANDLE h,DWORD wanted) {
    CHECK(WaitForSingleObject(h,5000)==WAIT_OBJECT_0);
    DWORD code;CHECK(GetExitCodeThread(h,&code) && code==wanted);
    for(unsigned i=1;i<BRIDGE_HANDLE_MAX;++i)if(s_handle_table[i]==h)s_handle_table[i]=NULL;
    CloseHandle(h);
}
int main(void) {
    memory=calloc(1,0x1000000);CHECK(memory);g_xbox_mem_offset=(ptrdiff_t)memory;main_tid=GetCurrentThreadId();
    uint32_t tops[8];
    for(unsigned i=0;i<8;++i){tops[i]=xbox_AllocThreadStack();CHECK(tops[i]==XBOX_STACK_BASE+(i+1)*XBOX_THREAD_STACK_SIZE-16);}
    CHECK(g_thread_stacks_used==8 && !xbox_AllocThreadStack() && g_thread_stacks_used==8);
    xbox_FreeThreadStack(0);xbox_FreeThreadStack(tops[0]-1);xbox_FreeThreadStack(tops[7]+XBOX_THREAD_STACK_SIZE);
    CHECK(g_thread_stacks_used==8);
    xbox_SetThreadMode(XBOX_THREAD_MODE_SPAWN);create(3,0,1);CHECK(!workers_entered);
    xbox_FreeThreadStack(tops[3]);CHECK(xbox_AllocThreadStack()==tops[3]);
    for(unsigned i=0;i<8;++i)xbox_FreeThreadStack(tops[i]);
    xbox_FreeThreadStack(tops[0]);CHECK(!g_thread_stacks_used);
    fail_malloc=1;create(1,0,1);CHECK(!g_thread_stacks_used && !startup_allocations);
    fail_create=1;create(1,0,1);CHECK(!g_thread_stacks_used && !startup_allocations);
    for(unsigned i=0;i<100;++i){HANDLE h=create(i&1?1:2,0,0);join(h,i&1?0:0x1234);CHECK(!g_thread_stacks_used && !startup_allocations);}
    CHECK(terminations==50);
    for(unsigned i=0;i<100;++i)CHECK(observed_tops[i]==tops[0]);
    LONG entered=workers_entered;HANDLE suspended=create(1,1,0);
    Sleep(20);CHECK(workers_entered==entered && g_thread_stacks_used==1 && startup_allocations==1);
    CHECK(ResumeThread(suspended)==1);join(suspended,0);CHECK(!g_thread_stacks_used && !startup_allocations);
    release_event=CreateEvent(NULL,TRUE,FALSE,NULL);CHECK(release_event);
    HANDLE live[8];for(unsigned i=0;i<8;++i)live[i]=create(3,0,0);
    for(unsigned tries=0;workers_entered<entered+9 && tries<500;++tries)Sleep(1);
    CHECK(workers_entered==entered+9 && g_thread_stacks_used==8);
    for(unsigned i=0;i<8;++i)for(unsigned j=0;j<i;++j)CHECK(observed_tops[entered+1+i]!=observed_tops[entered+1+j]);
    create(3,0,1);CHECK(g_thread_stacks_used==8 && workers_entered==entered+9);
    SetEvent(release_event);for(unsigned i=0;i<8;++i)join(live[i],0);CloseHandle(release_event);
    CHECK(!g_thread_stacks_used && !startup_allocations);
    xbox_SetThreadMode(XBOX_THREAD_MODE_INLINE);g_thread_call_count=0;
    g_esp=0xF70000;g_ecx=0xAABBCCDD;
    STACK_ARG(0)=0x10000;STACK_ARG(5)=0x12345678;STACK_ARG(6)=0x87654321;STACK_ARG(7)=0;STACK_ARG(9)=4;
    bridge_PsCreateSystemThreadEx();CHECK(g_eax==0 && g_esp==0xF70000 && BRIDGE_MEM32(0x10000)==0xBEEF0001 && !g_thread_stacks_used);
    puts("PASS: native stack lifecycle; 8-live exhaustion never runs inline, 100 normal/terminate reuses, malloc/CreateThread rollback, suspended ownership, context/output and parent GPR/ESP ABI, first INLINE preserved");
    return 0;
}
'''
vcvars = Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat')
native = prefix+'\n'.join(functions)+suffix
historical_allocator = r'''
uint32_t xbox_AllocThreadStack(void) {
    int index=InterlockedIncrement((volatile LONG *)&g_thread_stacks_used)-1;
    if(index>=8)return 0;
    return XBOX_STACK_BASE+(index+1)*XBOX_THREAD_STACK_SIZE-16;
}
'''
mutants = [
    ('historical_monotonic', native.replace(functions[0],historical_allocator)),
    ('missing_terminate_release', native.replace('        bridge_release_thread_stack();\n        ExitThread(exit_status);','        ExitThread(exit_status);')),
    ('historical_inline_exhaustion', native.replace('                    g_eax = 0xC000009Au; /* STATUS_INSUFFICIENT_RESOURCES */\n                    return;','                    bridge_run_thread_inline(fn, start_context1, start_context2);\n                    return;',1)),
]
for name,code in mutants: assert code!=native,name
with tempfile.TemporaryDirectory(prefix='dah2-thread-stacks-') as directory:
    out = Path(directory)
    for name,code,fail in [('repaired',native,False)]+[(n,c,True) for n,c in mutants]:
        (out / f'{name}.c').write_text(code, encoding='utf-8')
        command = f'call "{vcvars}" >nul && cl /nologo /Od /TC {name}.c /Fe:{name}.exe'
        subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
        result = subprocess.run([str(out / f'{name}.exe')],capture_output=True,text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
        if fail:
            assert result.returncode==3,(name,result.returncode,result.stdout,result.stderr)
            print('PASS: '+name+' mutant rejected')
        else:
            if result.returncode: print(result.stdout+result.stderr)
            result.check_returncode()
            print(result.stdout,end='')
