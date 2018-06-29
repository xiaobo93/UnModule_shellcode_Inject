#pragma once
#include"stdafx.h"
#include <Windows.h>
typedef struct _SHELL_CODE_PARAM
{
	LPVOID lpFileBase;
	LPVOID lpReserved;
	LPVOID lpProcName;
	LPVOID lpRunCmd;
}SHELL_CODE_PARAM, *PSHELL_CODE_PARAM;


#define SHELL_CODE_SIZE_X86		7753
extern unsigned char g_shellcode_x86[SHELL_CODE_SIZE_X86] ;
#define SHELL_CODE_SIZE_X64		9307
extern unsigned char g_shellcode_x64[SHELL_CODE_SIZE_X64];
#ifdef _WIN64
#define SHELL_CODE_SIZE	SHELL_CODE_SIZE_X64
#define g_shellcode	g_shellcode_x64
#else
#define SHELL_CODE_SIZE	SHELL_CODE_SIZE_X86
#define g_shellcode	g_shellcode_x86
#endif

#include"wow64ext\wow64ext.h"

//32位的进程注入32位进程，32位的DLL
//64位的进程注入64位进程，64位的dll
BOOL ModuleLessInject(HANDLE hProcess, PVOID lpFileBase, SIZE_T ImageSize, LPCTSTR szReserved, LPCSTR szProcName, LPCTSTR szRunCmd);

//32位的进程注入64位进程，64位的DLL
#ifndef _WIN64
BOOL Wow64ModuleLessInjectToX64(HANDLE hProcess, PVOID lpFileBase, SIZE_T ImageSize, LPCTSTR szReserved, LPCSTR szProcName, LPCTSTR szRunCmd);
#endif // !_WIN64

//64位的进程注入32位进程,32位的DLL
BOOL X64ModuleLessInjectToWow64(HANDLE hProcess, PVOID lpFileBase, SIZE_T ImageSize, LPCTSTR szReserved, LPCSTR szProcName, LPCTSTR szRunCmd);