# HookProc
This library is a wrapper for SetWindowsHookEx. It redirects hook events to a specified window message and returns the output. 
Most of these hooks have the ability to freeze essential functionalities such as creating windows, so the event handling code needs to be very carefully written or you might freeze your system and need to reboot to unfreeze.

## Main functions
### HANDLE SetHook(_In_ int idHook, _In_ UINT uMsg, _In_ DWORD dwThreadId, _In_ LONG_PTR* lpMsgArr, _In_ int nMsgArr, _In_ HWND hTargetWnd, _In_ DWORD uTimeout);
Sets a new hook using SetWindowsHookEx, using this dll for injection. Returns a handle to the hook, which can be used only by the script that created it.
- uMsg needs to be a message (eg from RegisterWindowMessage) which is used by SendMessage to communicate between the dll and AHK script.
- lpMsgArr is an array of monitored nCodes, maximum of 9 values. 
	- This limitation is set because of how slow AHK is, and how slow inter-process communication is.
	- 0xFFFFFFFF to match any nCode.
	- In the case of WH_CALLWNDPROC this should be an array of monitored window messages (eg WM_PASTE)
- nMsgArr is the number of elements in lpMsgArr.
- hTargetWnd is the window SendMessage targets, usually A_ScriptHwnd
- uTimeout specifies a timeout in milliseconds, which is highly recommended to be set to avoid freezes.

### LRESULT UnHook(_In_ HHOOK hHandle);
Unhooks the hook and removes it from shared memory.

### LRESULT Close();
Unhooks all hooks created by the same caller, and removes them from memory.

### LRESULT ClearSharedMemory();
Clears the shared memory space of all previous hook info. This is mainly used for debugging (eg when a script unexpectedly crashes and doesn't clean up after itself).

# Limitations
* lpMsgArr maximum size is 9 elements.
* Maximum number of hooks is 16.
* Slow: on my setup each call takes about 200 microseconds.
* HCBT_CREATEWND CBT_CREATEWND -> CREATESTRUCT -> lpszName and lpszClass can't be accessed

# Dev notes
When a new hook is added:
1. The hook index (starting from 0, max 15) is bound to the corresponding Proc function (eg CBTProc), creating a thunk
2. The thunk is stored in a shared memory space (file mapping) pSharedFile/pSharedArray
3. The thunk is copied over to a local mThunks variable
4. The rest of the shared memory space which is allocated to thunks is filled with stubs (pointing to StubProc), which when called will try to update mThunks
5. SetWindowsHookEx is given an address in mThunks

This method is most likely not safe nor secure, so use it at your own risk.

Shared memory space is automatically loaded on Dll process attach, and subsequently copied to mThunks. A local copy of the hook info is kept in HookProc static variable cachedInfo, which is updated when a matching index is not found (eg when StubProc is called), and in that case mThunks is also updated.

When a Proc function is called, it tries to locate its index from cachedInfo and stores it in the local scope. Then a process handle to AHK is opened, and SendMessage is used to send all info to the receiver. The receiver can use ReadRemoteMemory/WriteRemoteMemory to access the proc info, and the return value is used as the LRESULT for the Proc function (except when the result is <0, in which case CallNextHookEx is called instead).
