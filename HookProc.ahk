class WindowsHookEx {
	; File name of the HookProc dll, is searched in A_WorkingDir, A_ScriptDir, A_ScriptDir\Lib\, and A_ScriptDir\Resources\
	static DllName := "HookProc.dll"
	; Initializes library at load-time
	static __New() {
		for loc in [A_WorkingDir "\" this.DllName, A_ScriptDir "\" this.DllName, A_ScriptDir "\Lib\" this.DllName, A_ScriptDir "\Resources\" this.DllName] {
			if FileExist(loc) {
				; WindowsHookEx.ClearSharedMemory() ; Might be useful to uncomment while debugging
				this.hLib := DllCall("LoadLibrary", "str", loc, "ptr")
				return
			}
		}
		throw Error("Unable to find " this.DllName " file!", -1)
	}
	/**
	 * Sets a new WindowsHookEx, which can be used to intercept window messages. 
	 * It can only be used with 64-bit AHK, to hook 64-bit programs.
	 * This has the potential to completely freeze your system and force a reboot, so use it at your
	 * own peril!
	 * @param {number} idHook The type of hook procedure to be installed. 
	 * Common ones: WH_GETMESSAGE := 3, WH_CALLWNDPROC := 4, WH_CBT := 5
	 * @param {number} msg The window message number where new events are directed to.
	 * Can be created with `msg := DllCall("RegisterWindowMessage", "str", "YourMessageNameHere", "uint")`
	 * @param {array} nCodes An array of codes to be monitored (max of 9). 
	 * For most hook types this can be one of nCode values (eg HCBT_MINMAX for WH_CBT), but in the
	 * case of WH_CALLWNDPROC this should be an array of monitored window messages (eg WM_PASTE).
	 * 
	 * nCode 0xFFFFFFFF can be used to match all nCodes, but the use of this is not recommended
	 * because of the slowness of AHK and inter-process communication, which might slow down the whole system.
	 * @param HookedWinTitle A specific window title or hWnd to hook. Specify 0 for a global hook (all programs).
	 * @param {number} timeOut Timeout in milliseconds for events. Set 0 for infinite wait, but this
	 * isn't recommended because of the high potential of freezing the system (all other incoming
	 * messages would not get processed!).
	 * @param ReceiverWinTitle The WinTitle or hWnd of the receiver who will get the event messages.
	 * Default is current script. 
	 * @returns {Object} New hook object which contains hook information, and when destroyed unhooks the hook.
	 */
	__New(idHook, msg, nCodes, HookedWinTitle := "", timeOut := 16, ReceiverWinTitle := A_ScriptHwnd) {
		if !IsInteger(HookedWinTitle) {
			if !(this.hWndTarget := WinExist(HookedWinTitle))
				throw TargetError("HookedWinTitle `"" HookedWinTitle "`" was not found!", -1)
		} else
			this.hWndTarget := HookedWinTitle
		if !(this.hWndReceiver := IsInteger(ReceiverWinTitle) ? ReceiverWinTitle : WinExist(ReceiverWinTitle))
			throw TargetError("Receiver window was not found!", -1)
		if !IsObject(nCodes) && IsInteger(nCodes)
			nCodes := [nCodes]
		this.threadId := DllCall("GetWindowThreadProcessId", "Ptr", this.hWndTarget, "Ptr", 0, "UInt")
		this.idHook := idHook, this.msg := msg, this.nCodes := nCodes, this.nTimeout := timeOut
		local pData := Buffer(nCodes.Length * A_PtrSize)
		for i, nCode in nCodes
			NumPut("ptr", nCode, pData, (i-1)*A_PtrSize)
		this.hHook := DllCall(WindowsHookEx.DllName "\SetHook", "int", idHook, "ptr", msg, "int", this.threadId, "ptr", pData, "int", nCodes.Length, "ptr", this.hWndReceiver, "int", timeOut, "ptr")
	}
	; Unhooks the hook, which is also automatically done when the hook object is destroyed
	static Unhook(hHook) => DllCall(this.DllName "\UnHook", "ptr", IsObject(hHook) ? hHook.hHook : hHook)
	; Clears the shared memory space of the dll which might sometimes get corrupted during debugging
	static ClearSharedMemory() => DllCall(this.DllName "\ClearSharedMemory")
	__Delete() => WindowsHookEx.UnHook(this.hHook)
	; Unhooks all hooks created by this script
	static Close() => DllCall(this.DllName "\Close")
}

TryReadProcessMemory(hProcess, lpBaseAddress, oBuffer, &nBytesRead?) {
	try return DllCall("ReadProcessMemory", "ptr", hProcess, "ptr", lpBaseAddress, "ptr", oBuffer, "int", oBuffer.Size, "int*", IsSet(nBytesRead) ? &nBytesRead:=0 : 0, "int") != 0
	return 0
}
HIWORD(DWORD) => ((DWORD>>16)&0xFFFF)
LOWORD(DWORD) => (DWORD&0xFFFF)
MAKEWORD(LOWORD, HIWORD) => (HIWORD<<16)|(LOWORD&0xFFFF)