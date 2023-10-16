#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <map>
#include <array>
#include <vector>
#include <set>
#include <chrono>
#include <utility>
#include <mutex>
using namespace std::chrono;

struct ProcInfo {
    int nCode;
    WPARAM wParam;
    LPARAM lParam;
};

struct NewWndProcInfo {
    HWND hWnd;
    UINT uMsg;
    WPARAM wParam;
    LPARAM lParam;
};

struct HookInfo {
    HHOOK hHook = 0;
    UINT uMsg = 0;
    HWND hTargetWnd = 0;
    UINT uTimeout = 100;
    DWORD idHook = 0;
    std::set<LONG_PTR> registeredCodes = {};
};

void OpenSharedMemory();
void CloseSharedMemory();
extern "C" __declspec(dllexport) HANDLE SetHook(_In_ int idHook, _In_ UINT uMsg, _In_ DWORD dwThreadId, _In_ LONG_PTR * lpMsgArr, _In_ int nMsgArr, _In_ HWND hTargetWnd, _In_ DWORD uTimeout);
extern "C" __declspec(dllexport) LRESULT UnHook(_In_ HHOOK hHandle);
extern "C" __declspec(dllexport) LRESULT ClearSharedMemory();
extern "C" __declspec(dllexport) LRESULT Close();
extern "C" __declspec(dllexport) LRESULT CALLBACK StubProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK CallWndProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK CallWndRetProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK CBTProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK DebugProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK ForegroundIdleProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK GetMsgProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK KeyboardProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK MouseProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK MsgFilterProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK ShellProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
extern "C" __declspec(dllexport) LRESULT CALLBACK SysMsgProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam);
LRESULT HookProc(int index, int idHook, int nCode, LONG_PTR info, LRESULT& CBResult, HHOOK& hHook);
extern "C" __declspec(dllexport) LRESULT CALLBACK NewWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT UpdateCallbackInfo(std::map<DWORD, HookInfo>& cachedInfo);

template<typename... Args> void slogf(Args... args);

#define pCW ((CWPSTRUCT*)lParam)

#define ERR_MAPFILE_UNAVAILABLE 1
#define ERR_INIT_FAILED 2
#define ERR_CB_MUTEX_UNAVAILABLE 3
#define ERR_CODE_NOT_FOUND 4

#define MAX_HOOK_FAILURES 3
#define SIZEOF_SHARED_FILE 6400
#define SIZEOF_BLOCK 16
#define STARTOF_CBINFO 2
#define STARTOF_HOOKS 16
#define SHARED_FILE_MUTEX_TIMEOUT 100
#define STARTOF_THUNKS 2304
#define MAX_SIZEOF_THUNK 256
#define MAX_NUM_OF_HOOKS 16

// WIN32 is NOT SUPPORTED, mainly it's missing the thunk function
#if _WIN64
TCHAR szCBMutex[] = TEXT("Local\\AutoHotkeyWindowsHookEventSemaphore");
TCHAR szSharedFileMutex[] = TEXT("Local\\AutoHotkeyWindowsHookSharedFileSemaphore");
TCHAR szSharedFileName[] = TEXT("Local\\AutoHotkeyWindowsHookSharedMemory");
#else
TCHAR szCBMutex[] = TEXT("Local\\AutoHotkeyWindowsHookEventSemaphore32");
TCHAR szSharedFileMutex[] = TEXT("Local\\AutoHotkeyWindowsHookSharedFileSemaphore32");
TCHAR szSharedFileName[] = TEXT("Local\\AutoHotkeyWindowsHookSharedMemory32");
#endif

// Shared memory layout consists of a pointer-sized array
// First 16 elements are: num_of_hooks, usedIndices, reserved for future use...
// Then 16 next 16-element blocks are:
// hHook, uMsg, target hWnd (script), idHook, threadId, timeout, nParams, nCode/msg ...

// total max size of hook info space is 16 * 18 * 8 = 2304 bytes (2048 + 256)
// then next 256 * 16 = 4096 bytes are allocated to shared mThunks
// total size of shared memory = 6400

HANDLE hMapFile = 0; // handle to the shared file mapping
LPVOID pSharedFile = 0;
LONG_PTR* pSharedArray; // pSharedFile but in 8-byte chunks for easier use
HINSTANCE hThisDll;
// SharedFileSemaphore is used as a mutex when writing to the shared memory
// ghCBSemaphore is currently not used, but could be used to limit concurrent SendMessages to AHK
HANDLE ghCBSemaphore = 0, ghSharedFileSemaphore = 0;
BOOL gbIsFirstProcess = 0; // used to check whether this dll is attached to AHK (it's set in SetHook)
std::map<HANDLE, std::pair<DWORD, WNDPROC>> gOldWndInfo; // used by WH_CALLWNDPROC to store old WndProc from SetWindowLongPtr
std::recursive_mutex processMutex; // mutex for cachedInfo (~local copy of shared memory) read-writes
unsigned char mThunks[4096], mStubThunk[MAX_SIZEOF_THUNK];
// gnCurrentInstalledHooks keeps track of used indices with bitwise shifts 
// eg. gnCurrentInstalledHooks & (1 << 5) means index 5 (6th hook) is created by this AHK script
int mStubThunkSize = 0, gnCurrentInstalledHooks = 0;

// Source: https://stackoverflow.com/questions/12136309/how-to-thunk-a-function-in-x86-and-x64-like-stdbind-in-c-but-dynamic
size_t vbind(
    void* (/* cdecl, stdcall, or thiscall */ *f)(), size_t param_count,
    unsigned char buffer[/* >= 128 + n * (5 + sizeof(int) + sizeof(void*)) */],
    size_t const i, void* const bound[], unsigned int const n, bool const thiscall)
{
    unsigned char* p = buffer;
    unsigned char s = sizeof(void*);
    unsigned char b = sizeof(int) == sizeof(void*) ? 2 : 3;  // log2(sizeof(void *))
    *p++ = 0x55;                                                                          // push     rbp
    if (b > 2) { *p++ = 0x48; } *p++ = 0x8B; *p++ = 0xEC;                                 // mov      rbp, rsp
    if (b > 2)
    {
        *p++ = 0x48; *p++ = 0x89; *p++ = 0x4C; *p++ = 0x24; *p++ = 2 * s;                 // mov      [rsp + 2 * s], rcx
        *p++ = 0x48; *p++ = 0x89; *p++ = 0x54; *p++ = 0x24; *p++ = 3 * s;                 // mov      [rsp + 3 * s], rdx
        *p++ = 0x4C; *p++ = 0x89; *p++ = 0x44; *p++ = 0x24; *p++ = 4 * s;                 // mov      [rsp + 4 * s], r8
        *p++ = 0x4C; *p++ = 0x89; *p++ = 0x4C; *p++ = 0x24; *p++ = 5 * s;                 // mov      [rsp + 5 * s], r9
    }
    if (b > 2) { *p++ = 0x48; } *p++ = 0xBA; *(*(size_t**)&p)++ = param_count;           // mov      rdx, <param_count>
    if (b > 2) { *p++ = 0x48; } *p++ = 0x8B; *p++ = 0xC2;                                 // mov      rax, rdx
    if (b > 2) { *p++ = 0x48; } *p++ = 0xC1; *p++ = 0xE0; *p++ = b;                       // shl      rax, log2(sizeof(void *))
    if (b > 2) { *p++ = 0x48; } *p++ = 0x2B; *p++ = 0xE0;                                 // sub      rsp, rax
    *p++ = 0x57;                                                                          // push     rdi
    *p++ = 0x56;                                                                          // push     rsi
    *p++ = 0x51;                                                                          // push     rcx
    *p++ = 0x9C;                                                                          // pushfq
    if (b > 2) { *p++ = 0x48; } *p++ = 0xF7; *p++ = 0xD8;                                 // neg      rax
    if (b > 2) { *p++ = 0x48; } *p++ = 0x8D; *p++ = 0x7C; *p++ = 0x05; *p++ = 0x00;       // lea      rdi, [rbp + rax]
    if (b > 2) { *p++ = 0x48; } *p++ = 0x8D; *p++ = 0x75; *p++ = 2 * s;                   // lea      rsi, [rbp + 10h]
    if (b > 2) { *p++ = 0x48; } *p++ = 0xB9; *(*(size_t**)&p)++ = i;                     // mov      rcx, <i>
    if (b > 2) { *p++ = 0x48; } *p++ = 0x2B; *p++ = 0xD1;                                 // sub      rdx, rcx
    *p++ = 0xFC;                                                                          // cld
    *p++ = 0xF3; if (b > 2) { *p++ = 0x48; } *p++ = 0xA5;                                 // rep movs [rdi], [rsi]
    for (unsigned int j = 0; j < n; j++)
    {
        unsigned int const o = j * sizeof(p);
        if (b > 2) { *p++ = 0x48; } *p++ = 0xB8; *(*(void***)&p)++ = bound[j];           // mov      rax, <arg>
        if (b > 2) { *p++ = 0x48; } *p++ = 0x89; *p++ = 0x87; *(*(int**)&p)++ = o;       // mov      [rdi + <iArg>], rax
    }
    if (b > 2) { *p++ = 0x48; } *p++ = 0xB8; *(*(size_t**)&p)++ = n;                     // mov      rax, <count>
    if (b > 2) { *p++ = 0x48; } *p++ = 0x2B; *p++ = 0xD0;                                 // sub      rdx, rax
    if (b > 2) { *p++ = 0x48; } *p++ = 0xC1; *p++ = 0xE0; *p++ = b;                       // shl      rax, log2(sizeof(void *))
    if (b > 2) { *p++ = 0x48; } *p++ = 0x03; *p++ = 0xF8;                                 // add      rdi, rax
    if (b > 2) { *p++ = 0x48; } *p++ = 0x8B; *p++ = 0xCA;                                 // mov      rcx, rdx
    *p++ = 0xF3; if (b > 2) { *p++ = 0x48; } *p++ = 0xA5;                                 // rep movs [rdi], [rsi]
    *p++ = 0x9D;                                                                          // popfq
    *p++ = 0x59;                                                                          // pop      rcx
    *p++ = 0x5E;                                                                          // pop      rsi
    *p++ = 0x5F;                                                                          // pop      rdi
    if (b > 2)
    {
        *p++ = 0x48; *p++ = 0x8B; *p++ = 0x4C; *p++ = 0x24; *p++ = 0 * s;                 // mov      rcx, [rsp + 0 * s]
        *p++ = 0x48; *p++ = 0x8B; *p++ = 0x54; *p++ = 0x24; *p++ = 1 * s;                 // mov      rdx, [rsp + 1 * s]
        *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x44; *p++ = 0x24; *p++ = 2 * s;                 // mov      r8 , [rsp + 2 * s]
        *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x4C; *p++ = 0x24; *p++ = 3 * s;                 // mov      r9 , [rsp + 3 * s]
        *p++ = 0x48; *p++ = 0xB8; *(*(void* (***)()) & p)++ = f;                            // mov      rax, <target_ptr>
        *p++ = 0xFF; *p++ = 0xD0;                                                         // call     rax
    }
    else
    {
        if (thiscall) { *p++ = 0x59; }                                                    // pop      rcx
        *p++ = 0xE8; *(*(ptrdiff_t**)&p)++ = (unsigned char*)f - p
#ifdef _MSC_VER
            - s  // for unknown reasons, GCC doesn't like this
#endif
            ;                                                                             // call     <fn_rel>
    }
    if (b > 2) { *p++ = 0x48; } *p++ = 0x8B; *p++ = 0xE5;                                            // mov      rsp, rbp
    *p++ = 0x5D;                                                                          // pop      rbp
    *p++ = 0xC3;                                                                          // ret
    return p - &buffer[0];
}

// Binds index to Proc and copies the created thunk to pSharedFile. Doesn't copy to local mThunks.
size_t AddThunk(int index, void* proc) {
    unsigned char thunk[MAX_SIZEOF_THUNK]; void* args[] = { (void*)index };
    size_t thunk_size = vbind((void* (*)())proc, 4, thunk, 0, args, sizeof(args) / sizeof(*args), false);
    memcpy(&(((unsigned char*)pSharedFile)[STARTOF_THUNKS + index * MAX_SIZEOF_THUNK]), thunk, MAX_SIZEOF_THUNK);
    return thunk_size;
}

template<typename... Args> void slogf(Args... args) {
    std::ofstream log(".\\logfile.txt", std::ios_base::out | std::ios_base::app);
    char debug[1000];
    sprintf_s(debug, args...);
    log << debug;
    log.close();
}

int GetFirstOpenIndex() {
    int index = -1;
    // Either get the spot after the last taken index, eg in case of 10100000... return 3
    for (int i = MAX_NUM_OF_HOOKS - 1; i >= 0; i--) {
        if ((int)pSharedArray[1] & (1 << i)) {
            if (i + 1 < MAX_NUM_OF_HOOKS) {
                return i + 1;
            }
            else
                break;
        }
    }
    // Otherwise return the first open spot
    for (int i = 0; i < MAX_NUM_OF_HOOKS; i++) {
        if (!((int)pSharedArray[1] & (1 << i))) {
            return i;
        }
    }
    return -1;
}

void OpenSharedMemory() {
    if (!hMapFile) {
        hMapFile = OpenFileMapping(
            FILE_MAP_ALL_ACCESS,   // read/write access
            FALSE,                 // do not inherit the name
            szSharedFileName);               // name of mapping object
    }

    if (hMapFile == NULL) {
        hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SIZEOF_SHARED_FILE, szSharedFileName);
        if (!hMapFile)
            return;
    }
    if (!pSharedFile) {
        pSharedFile = (LPVOID)MapViewOfFile(hMapFile,   // handle to map object
            FILE_MAP_ALL_ACCESS, // read/write permission
            0,
            0,
            SIZEOF_SHARED_FILE);
    }

    if (pSharedFile)
        pSharedArray = (LONG_PTR*)pSharedFile;
}

void CloseSharedMemory() {
    if (pSharedFile)
        UnmapViewOfFile(pSharedFile);
    if (hMapFile)
        CloseHandle(hMapFile);
    pSharedFile = 0; pSharedArray = 0; hMapFile = 0;
}

// Unhooks running hooks and then clears shared memory. Make sure no hook is running when this is done.
extern "C" __declspec(dllexport) LRESULT ClearSharedMemory() {
    if (!pSharedArray)
        return 1;
    for (int i = STARTOF_HOOKS; i < STARTOF_HOOKS + MAX_NUM_OF_HOOKS * SIZEOF_BLOCK; i += SIZEOF_BLOCK) {
        if (pSharedArray[i]) {
            UnhookWindowsHookEx((HHOOK)pSharedArray[i]);
        }
    }
    RtlFillMemory(pSharedArray, SIZEOF_SHARED_FILE, 0);
    for (int i = 0; i < MAX_NUM_OF_HOOKS * MAX_SIZEOF_THUNK; i += MAX_SIZEOF_THUNK) {
        memcpy(&(((unsigned char*)pSharedFile)[STARTOF_THUNKS + i]), mStubThunk, MAX_SIZEOF_THUNK);
        memcpy(&(mThunks[i]), mStubThunk, MAX_SIZEOF_THUNK);
    }
    return 0;
}

// Updates cachedInfo from shared memory
LRESULT UpdateCallbackInfo(std::map<DWORD, HookInfo>& cachedInfo) {
    if (!pSharedArray[0]) {
        return ERROR_INVALID_INDEX;
    }

    DWORD dwWaitResult = WaitForSingleObject(ghSharedFileSemaphore, SHARED_FILE_MUTEX_TIMEOUT);
    if (dwWaitResult != WAIT_OBJECT_0) {
        return ERROR_TIMEOUT;
    }

    cachedInfo.clear();
    int j = 0;
    for (int i = STARTOF_HOOKS; i < STARTOF_HOOKS + MAX_NUM_OF_HOOKS * SIZEOF_BLOCK; i += SIZEOF_BLOCK) {
        if (!((int)pSharedArray[1] & (1 << j))) {
            j++;
            continue;
        }

        cachedInfo[j] = HookInfo{};

        HookInfo& hookInfo = cachedInfo[j];
        hookInfo.hHook = (HHOOK)pSharedArray[i];
        hookInfo.uMsg = (UINT)pSharedArray[i + 1];
        hookInfo.hTargetWnd = (HWND)pSharedArray[i + 2];
        hookInfo.registeredCodes = {};
        hookInfo.uTimeout = (int)pSharedArray[i + 5];

        int start = i + 7, end = start + (int)pSharedArray[i + 6];
        for (int j = start; j < end; j++)
            hookInfo.registeredCodes.insert(pSharedArray[j]);

        j++;
    }

    memcpy(mThunks, &((unsigned char*)pSharedFile)[STARTOF_THUNKS], MAX_NUM_OF_HOOKS * MAX_SIZEOF_THUNK);

    ReleaseSemaphore(ghSharedFileSemaphore, 1, 0);

    if (!cachedInfo.size())
        return ERR_CODE_NOT_FOUND;
    return 0;
}

void RemoveIndexFromSharedMemory(int index) {
    if (index < 0 || index >= MAX_NUM_OF_HOOKS)
        return;
    if (!(gnCurrentInstalledHooks & (1 << index))) // cannot be uninstalled by us (simply doesn't do anything)
        return;
    int i = STARTOF_HOOKS + index * SIZEOF_BLOCK;
    if ((HHOOK)pSharedArray[i] != NULL)
        UnhookWindowsHookEx((HHOOK)pSharedArray[i]);
    memcpy(&((unsigned char*)pSharedFile)[STARTOF_THUNKS + index * MAX_SIZEOF_THUNK], mStubThunk, MAX_SIZEOF_THUNK);
    memcpy(&mThunks[index * MAX_SIZEOF_THUNK], mStubThunk, MAX_SIZEOF_THUNK);
    RtlFillMemory(&pSharedArray[i], SIZEOF_BLOCK * sizeof(LONG_PTR), 0);
    pSharedArray[0] = (LONG_PTR)((int)pSharedArray[0] - 1);
    pSharedArray[1] = (int)pSharedArray[1] & ~(1 << index);
    // keep track which indexes are used
    gnCurrentInstalledHooks &= ~(1 << index);
}

void RemoveHookFromSharedMemory(HHOOK hHandle) {
    if (!hHandle)
        return;
    if (!hMapFile) {
        OpenSharedMemory();
    }
    if (!hMapFile || !pSharedArray) {
        return;
    }
    DWORD dwWaitResult = WaitForSingleObject(ghSharedFileSemaphore, SHARED_FILE_MUTEX_TIMEOUT);
    if (dwWaitResult != WAIT_OBJECT_0)
        return;

    int j = 0;
    for (int i = STARTOF_HOOKS; i < STARTOF_HOOKS + MAX_NUM_OF_HOOKS * SIZEOF_BLOCK; i += SIZEOF_BLOCK) {
        if ((gnCurrentInstalledHooks & (1 << j)) && (HHOOK)pSharedArray[i] == hHandle) {
            RemoveIndexFromSharedMemory(j);
            break;
        }
        j++;
    }
    ReleaseSemaphore(ghSharedFileSemaphore, 1, 0);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    hThisDll = hinstDLL;
    void* args[] = { (void*)-1 };
    DWORD dwWaitResult = 1;
    int j = 0;

    switch (fdwReason)
    {
    case DLL_THREAD_ATTACH:
        break;
    case DLL_PROCESS_ATTACH: // global variables are shared between threads, so init only for process is enough
        ghCBSemaphore = OpenSemaphore(SEMAPHORE_MODIFY_STATE | SYNCHRONIZE, 0, szCBMutex);
        ghSharedFileSemaphore = OpenSemaphore(SEMAPHORE_MODIFY_STATE | SYNCHRONIZE, 0, szSharedFileMutex);
        OpenSharedMemory();

        // create a stub to which all calls to unknown thunks are forwarded
        mStubThunkSize = vbind((void* (*)())StubProc, 4, mStubThunk, 0, args, sizeof(args) / sizeof(*args), false);

        if (ghSharedFileSemaphore)
            dwWaitResult = WaitForSingleObject(ghSharedFileSemaphore, SHARED_FILE_MUTEX_TIMEOUT);
        // copy stub thunks and thunks to mThunk
        j = 0;
        for (int i = 0; i < MAX_NUM_OF_HOOKS * MAX_SIZEOF_THUNK; i += MAX_SIZEOF_THUNK) {
            if ((pSharedArray[1] & (1 << j)) && (dwWaitResult == WAIT_OBJECT_0))
                memcpy(&mThunks[i], &(((unsigned char*)pSharedFile)[STARTOF_THUNKS + i]), MAX_SIZEOF_THUNK);
            else
                memcpy(&(mThunks[i]), mStubThunk, MAX_SIZEOF_THUNK);
            j++;
        }

        if (dwWaitResult == WAIT_OBJECT_0)
            ReleaseSemaphore(ghSharedFileSemaphore, 1, 0);

        unsigned long old;

        VirtualProtect(mThunks, MAX_SIZEOF_THUNK * MAX_NUM_OF_HOOKS, PAGE_EXECUTE_READWRITE, &old);

        if (!hMapFile)
            return false;
        break;

    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:

        dwWaitResult = WaitForSingleObject(ghSharedFileSemaphore, SHARED_FILE_MUTEX_TIMEOUT);

        if (gbIsFirstProcess && pSharedArray) {
            for (int i = 0; i < MAX_NUM_OF_HOOKS; i++) {
                if (gnCurrentInstalledHooks & (1 << i)) {
                    RemoveIndexFromSharedMemory(i);
                }
            }
            SendNotifyMessage(HWND_BROADCAST, WM_NULL, 0, 0); // or should a heartbeat thread be implemented in each attached dll?
        }

        if (dwWaitResult == WAIT_OBJECT_0)
            ReleaseSemaphore(ghSharedFileSemaphore, 1, 0);

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }
        CloseHandle(ghCBSemaphore); ghCBSemaphore = 0;
        CloseHandle(ghSharedFileSemaphore); ghSharedFileSemaphore = 0;
        CloseSharedMemory();

        break;
    }
    return true;
}

extern "C" __declspec(dllexport) LRESULT Close() {
    if (pSharedFile && ghSharedFileSemaphore) {
        DWORD dwWaitResult = WaitForSingleObject(ghSharedFileSemaphore, SHARED_FILE_MUTEX_TIMEOUT);
        for (int i = 0; i < MAX_NUM_OF_HOOKS; i++) {
            if (gnCurrentInstalledHooks & (1 << i)) {
                RemoveIndexFromSharedMemory(i);
            }
        }
        if (dwWaitResult == WAIT_OBJECT_0)
            ReleaseSemaphore(ghSharedFileSemaphore, 1, 0);
    }
    return 0;
}

extern "C" __declspec(dllexport) HANDLE SetHook(_In_ int idHook, _In_ UINT uMsg, _In_ DWORD dwThreadId, _In_ LONG_PTR * lpMsgArr, _In_ int nMsgArr, _In_ HWND hTargetWnd, _In_ DWORD dwTimeout) {
    if (!gbIsFirstProcess) {
        if (!ghCBSemaphore) {
            ghCBSemaphore = CreateSemaphore(
                NULL,               // default security attributes
                1,
                1,
                szCBMutex  // object name
            );
        }
        if (!ghCBSemaphore) {
            ghCBSemaphore = OpenSemaphore(SEMAPHORE_ALL_ACCESS, 0, szCBMutex);
        }
        if (!ghSharedFileSemaphore) {
            ghSharedFileSemaphore = CreateSemaphore(
                NULL,               // default security attributes
                1,
                1,// initially not owned
                szSharedFileMutex  // object name
            );
        }
        if (!ghSharedFileSemaphore) {
            ghSharedFileSemaphore = OpenSemaphore(SEMAPHORE_ALL_ACCESS, 0, szSharedFileMutex);
        }
        if (!ghCBSemaphore || !ghSharedFileSemaphore) {
            return 0;
        }

        ReleaseSemaphore(ghCBSemaphore, 1, 0);
        ReleaseSemaphore(ghSharedFileSemaphore, 1, 0);

        gbIsFirstProcess = true;
    }

    void* proc = CBTProc;
    switch (idHook) {
    case WH_CALLWNDPROC:
        proc = CallWndProc; break;
    case WH_CALLWNDPROCRET:
        proc = CallWndRetProc; break;
    case WH_CBT:
        proc = CBTProc; break;
    case WH_DEBUG:
        proc = DebugProc; break;
    case WH_FOREGROUNDIDLE:
        proc = ForegroundIdleProc; break;
    case WH_GETMESSAGE:
        proc = GetMsgProc; break;
    case WH_KEYBOARD:
        proc = KeyboardProc; break;
    case WH_MOUSE:
        proc = MouseProc; break;
    case WH_MSGFILTER:
        proc = MsgFilterProc; break;
    case WH_SHELL:
        proc = ShellProc; break;
    case WH_SYSMSGFILTER:
        proc = SysMsgProc; break;
    }

    int index = GetFirstOpenIndex();
    if (index < 0)
        return 0;

    DWORD dwWaitResult = WaitForSingleObject(ghSharedFileSemaphore, SHARED_FILE_MUTEX_TIMEOUT);
    if (dwWaitResult != WAIT_OBJECT_0) {
        return 0;
    }

    size_t thunk_size = AddThunk(index, proc); // copies only to pSharedArray, not to local
    memcpy(&mThunks[index * MAX_SIZEOF_THUNK], &(((unsigned char*)pSharedFile)[STARTOF_THUNKS + index * MAX_SIZEOF_THUNK]), MAX_SIZEOF_THUNK); // in case code gets called from our own script 

    HHOOK hHook = SetWindowsHookEx(idHook, (HOOKPROC) & (mThunks[index * MAX_SIZEOF_THUNK]), hThisDll, dwThreadId);

    if (hHook) {
        pSharedArray[0] = (LONG_PTR)((int)pSharedArray[0] + 1);
        gnCurrentInstalledHooks |= (1 << index);
        pSharedArray[1] = (LONG_PTR)((int)pSharedArray[1] | (1 << index));
        int offset = STARTOF_HOOKS + index * SIZEOF_BLOCK;
        pSharedArray[offset] = (LONG_PTR)hHook;
        pSharedArray[offset + 1] = (LONG_PTR)uMsg;
        pSharedArray[offset + 2] = (LONG_PTR)hTargetWnd;
        pSharedArray[offset + 3] = (LONG_PTR)idHook;
        pSharedArray[offset + 4] = (LONG_PTR)dwThreadId;
        pSharedArray[offset + 5] = dwTimeout <= 0 ? 0xFFFFFFFF : dwTimeout;
        pSharedArray[offset + 6] = (LONG_PTR)nMsgArr;
        CopyMemory(&((pSharedArray)[offset + 7]), lpMsgArr, min(nMsgArr, (SIZEOF_BLOCK - 7)) * sizeof(LONG_PTR));
    }

    ReleaseSemaphore(ghSharedFileSemaphore, 1, 0);
    return hHook;
}

extern "C" __declspec(dllexport) LRESULT UnHook(_In_ HHOOK hHandle) {
    RemoveHookFromSharedMemory(hHandle);
    return 0;
}

extern "C" __declspec(dllexport) LRESULT CALLBACK StubProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (index == -1) {
        LRESULT CBResult = 0; HHOOK hHook = 0; ProcInfo info = {};
        // call HookProc with stub values to force an update of cache
        HookProc(MAX_NUM_OF_HOOKS, 123, 12345, (LONG_PTR)&info, CBResult, hHook);
    }
    return CallNextHookEx(0, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK CallWndProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    HHOOK hHook = (HHOOK)pCW->wParam;
    HWND hVLWnd = pCW->hwnd;

    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);

    ProcInfo info = { nCode, wParam, lParam };
    HHOOK thisHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_CALLWNDPROC, pCW->message, (LONG_PTR)&info, CBResult, thisHook);

    if (pCW->message == WM_PASTE) {
        auto found = gOldWndInfo.find(hVLWnd);
        if (found == gOldWndInfo.end()) {
            //gOldWndInfo[hVLWnd] = (WNDPROC)SetWindowLongPtr(hVLWnd, GWLP_WNDPROC, (LRESULT)NewWndProc);
        } // otherwise the proc is already set probably
    }

    return CallNextHookEx(thisHook, nCode, wParam, lParam);
}

LRESULT CALLBACK NewWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    LONG_PTR paramArray[4] = { (LONG_PTR)hWnd, (LONG_PTR)uMsg, (LONG_PTR)wParam, (LONG_PTR)lParam };

    // In any case reset the WndProc back to the old one
    processMutex.lock();
    auto found = gOldWndInfo.find(hWnd);
    WNDPROC WndProc = NULL;
    int index = -1;
    if (found != gOldWndInfo.end() && found->second.second) {
        index = found->second.first;
        WndProc = found->second.second;
        (WNDPROC)SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LRESULT)(WndProc));
        gOldWndInfo.erase(found);
    }
    processMutex.unlock();
    if (index < 0)
        return 0;
    NewWndProcInfo info = { hWnd, uMsg, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult = 0, result = HookProc(index, WH_CALLWNDPROC | 0xF000, uMsg, (LONG_PTR)&info, CBResult, hHook);

    if (result == 0 && CBResult >= 0)
        return CBResult;

    return WndProc ? CallWindowProc(WndProc, hWnd, uMsg, wParam, lParam) : 0;
}

extern "C" __declspec(dllexport) LRESULT CALLBACK CallWndRetProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_CALLWNDPROCRET, nCode, (LONG_PTR)&info, CBResult, hHook);
    if (result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

/*
    Current limitations:
    1) HCBT_CREATEWND CBT_CREATEWND -> CREATESTRUCT -> lpszName and lpszClass can't be accessed
    Also, lpszClass might not be a string at all, but instead an ATOM, treating which as a string will
    crash the program. See more: https://stackoverflow.com/questions/20583493/cbt-createwnd-structure-has-invalid-name

*/
extern "C" __declspec(dllexport) LRESULT CALLBACK CBTProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;

    auto start = high_resolution_clock::now();

    LRESULT CBResult = 0, result = HookProc(index, WH_CBT, nCode, (LONG_PTR)&info, CBResult, hHook);

    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);

    if (result == 0) {
        if (CBResult < 0)
            return CallNextHookEx(hHook, nCode, wParam, lParam);
        else
            return CBResult;
    }

    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK DebugProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_DEBUG, nCode, (LONG_PTR)&info, CBResult, hHook);
    if (result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK ForegroundIdleProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_FOREGROUNDIDLE, nCode, (LONG_PTR)&info, CBResult, hHook);
    if (result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK GetMsgProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_GETMESSAGE, nCode, (LONG_PTR)&info, CBResult, hHook);
    if (result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK KeyboardProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_KEYBOARD, nCode, (LONG_PTR)&info, CBResult, hHook);
    if (result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK MouseProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_MOUSE, nCode, (LONG_PTR)&info, CBResult, hHook);
    if (result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK MsgFilterProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_MSGFILTER, nCode, (LONG_PTR)&info, CBResult, hHook);
    if (result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK ShellProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    // This takes about 80-100 micros, of which making the AHK call takes 40 micros
    LRESULT CBResult, result = HookProc(index, WH_SHELL, nCode, (LONG_PTR)&info, CBResult, hHook);

    if (nCode == HSHELL_APPCOMMAND && result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK SysMsgProc(_In_ int index, _In_ int nCode, _In_ WPARAM wParam, _In_ LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(nullptr, nCode, wParam, lParam);
    ProcInfo info = { nCode, wParam, lParam };
    HHOOK hHook = 0;
    LRESULT CBResult, result = HookProc(index, WH_SYSMSGFILTER, nCode, (LONG_PTR)&info, CBResult, hHook);
    if (result == 0) return CBResult < 0 ? CallNextHookEx(hHook, nCode, wParam, lParam) : CBResult;
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

LRESULT HookProc(int index, int idHook, int nCode, LONG_PTR info, LRESULT& CBResult, HHOOK& hHook) {
    static std::map<DWORD, HookInfo> cachedInfo = {};

    if (!hMapFile || !pSharedArray) {
        return ERR_MAPFILE_UNAVAILABLE;
    }

    if (!ghSharedFileSemaphore || !ghCBSemaphore) {
        return ERR_CB_MUTEX_UNAVAILABLE;
    }

    processMutex.lock();

    if (cachedInfo.find(index) == cachedInfo.end()) {
        LRESULT result = UpdateCallbackInfo(cachedInfo);
        if (result) {
            processMutex.unlock();
            return result;
        }
        if (cachedInfo.find(index) == cachedInfo.end()) {
            processMutex.unlock();
            return ERROR_NOT_FOUND;
        }
    }

    DWORD usedThreadId = GetCurrentThreadId();
    auto hookInfo = cachedInfo[index];

    if (hookInfo.registeredCodes.find(nCode) == hookInfo.registeredCodes.end() && hookInfo.registeredCodes.find(0xFFFFFFFF) == hookInfo.registeredCodes.end()) {
        processMutex.unlock();
        return ERROR_NOT_FOUND;
    }

    hHook = hookInfo.hHook;
    UINT uMsg = hookInfo.uMsg;
    HWND hTargetWnd = hookInfo.hTargetWnd;
    UINT uTimeout = hookInfo.uTimeout;

    processMutex.unlock();


    if (idHook == WH_CALLWNDPROC) { // in this case 
        processMutex.lock();
        HWND hVLWnd = ((CWPSTRUCT*)(((ProcInfo*)info)->lParam))->hwnd;
        auto found = gOldWndInfo.find(hVLWnd);
        if (found == gOldWndInfo.end()) {
            gOldWndInfo[hVLWnd] = { index, (WNDPROC)SetWindowLongPtr(hVLWnd, GWLP_WNDPROC, (LRESULT)NewWndProc) };
            CBResult = 0; // prevent
            processMutex.unlock();
            return 0;
        }
        processMutex.unlock();
    }



    HANDLE hCurrentProc = GetCurrentProcess(), hDuplicate = 0, hTargetProc = 0;
    DWORD targetPID = 0;
    if (hTargetWnd)
        GetWindowThreadProcessId(hTargetWnd, &targetPID);

    if (targetPID)
        hTargetProc = OpenProcess(PROCESS_DUP_HANDLE, 0, targetPID);
    if (!hTargetProc) {
        // main process is probably dead, so exit
        RemoveIndexFromSharedMemory(index);
        return ERROR_CLASS_DOES_NOT_EXIST;
    }

    DuplicateHandle(hCurrentProc,
        hCurrentProc,
        hTargetProc,
        &hDuplicate,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS);

    if (!hDuplicate) {
        return ERROR_ACCESS_DENIED;
    }


    LRESULT result = 1;
    if (uTimeout == INFINITE)
        CBResult = SendMessage(hTargetWnd, uMsg, (WPARAM)hDuplicate, (LPARAM)info);
    else {
        result = SendMessageTimeout(hTargetWnd, uMsg, (WPARAM)hDuplicate, (LPARAM)info, 0, uTimeout, (PDWORD_PTR)&CBResult);
    }

    CloseHandle(hCurrentProc);
    CloseHandle(hTargetProc);

    return result == 0 ? GetLastError() : 0;
}