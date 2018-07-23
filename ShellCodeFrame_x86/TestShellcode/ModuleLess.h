#ifndef _MODULELESS_H_
#define _MODULELESS_H_

typedef struct _SHELL_CODE_PARAM
{
	PVOID lpFileBase;
	LPVOID lpReserved;
	LPVOID lpProcName;
	LPVOID lpRunCmd;
}SHELL_CODE_PARAM, *PSHELL_CODE_PARAM;

typedef BOOL  (WINAPI *DLL_MAIN)( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved);

typedef VOID (WINAPI *pRunDll)(LPCWSTR pszRunCmd);

namespace CModuleLess
{
	BOOL ModuleLessLoad(PVOID lpFileBase,SIZE_T ImageSize, LPCTSTR szReserved, LPCSTR szProcName, LPCTSTR szRunCmd);
	void ShellCodeModuleLessLoad(PVOID lpFileBase,SIZE_T ImageSize, LPCTSTR szReserved, LPCSTR szProcName, LPCTSTR szRunCmd);
	BOOL ModuleLessInject(DWORD dwProcessId, PVOID lpFileBase, SIZE_T ImageSize, LPCTSTR szReserved, LPCSTR szProcName, LPCTSTR szRunCmd);
	BOOL Wow64ModuleLessInjectToX64(DWORD dwProcessId, PVOID lpFileBase, SIZE_T ImageSize, LPCTSTR szReserved, LPCSTR szProcName, LPCTSTR szRunCmd);
}

#endif