#pragma once

#include "nativeapi.h"


#pragma pack(push)
#pragma pack(1)
typedef struct _ShellData
{

	BOOL									bIsInitSucess;
	HMODULE									base_ker32;
	HMODULE									base_ntdll;
			

	TCreateFileA							xCreateFileA;
	TCreateFileW							xCreateFileW;
	TCreateFileMappingA						xCreateFileMappingA;
	TCloseHandle							xCloseHandle;
	TCreateToolhelp32Snapshot				xCreateToolhelp32Snapshot;
	TCheckRemoteDebuggerPresent				xCheckRemoteDebuggerPresent;
	TCreateHardLinkA						xCreateHardLinkA;
	TCreateHardLinkW						xCreateHardLinkW;
	TCopyFileA								xCopyFileA;
	TCopyFileW								xCopyFileW;
	TCreateDirectoryA						xCreateDirectoryA;
	TCreateDirectoryW						xCreateDirectoryW;
	TCreateDesktopA							xCreateDesktopA;
	TCreateDesktopW							xCreateDesktopW;
	TCreateProcessA							xCreateProcessA;
	TCreateProcessW							xCreateProcessW;

	TDeleteFileA							xDeleteFileA;
	TDeleteFileW							xDeleteFileW;

	TExitProcess							xExitProcess;
	TFindResourceA							xFindResourceA;

	TGetProcessHeap							xGetProcessHeap;
	TGlobalFree								xGlobalFree;
	TGetSystemDirectoryA					xGetSystemDirectoryA;
	TGetProcAddress 						xGetProcAddress;
	TGetModuleHandleA						xGetModuleHandleA;	
	TGetFileSize							xGetFileSize;
	TGetCurrentProcess						xGetCurrentProcess;
	TGetProcessImageFileNameA				xGetProcessImageFileNameA;
	TGetLastError							xGetLastError;
	TGetStartupInfoA						xGetStartupInfoA;
	TGetTickCount							xGetTickCount;
	TGetCurrentProcessId					xGetCurrentProcessId;
	TGetNativeSystemInfo					xGetNativeSystemInfo;
	TGetModuleFileNameA						xGetModuleFileNameA;
	TGetShortPathNameA						xGetShortPathNameA;	
	TGetSystemDirectoryW					xGetSystemDirectoryW;
	TGetEnvironmentVariableA				xGetEnvironmentVariableA;
	TGetEnvironmentVariableW				xGetEnvironmentVariableW;
	TGetPrivateProfileStringA				xGetPrivateProfileStringA;
	TGetPrivateProfileStringW				xGetPrivateProfileStringW;
	TGetThreadContext						xGetThreadContext;
	TSetThreadContext						xSetThreadContext;

	THeapAlloc								xHeapAlloc;
	THeapFree								xHeapFree;

	TIsDebuggerPresent						xIsDebuggerPresent;
	TIsWow64Process							xIsWow64Process;

	TNtCreateFile							xNtCreateFile;

	TLoadResource							xLoadResource;
	TLockResource							xLockResource;
	TLoadLibraryA 							xLoadLibraryA;

	TMapViewOfFile							xMapViewOfFile;
	TMultiByteToWideChar					xMultiByteToWideChar;
	TMoveFileA								xMoveFileA;
	TMoveFileW								xMoveFileW;
	TMoveFileExA							xMoveFileExA;
	TMoveFileExW							xMoveFileExW;

	TOutputDebugStringA 					xOutputDebugStringA;
	TOpenProcess							xOpenProcess;
	TOpenThread								xOpenThread;

	TProcess32First							xProcess32First;
	TProcess32Next							xProcess32Next;

	TRtlAllocateHeap						xRtlAllocateHeap;
	TRtlFreeHeap							xRtlFreeHeap;
	TReadFile								xReadFile;			
	TRtlAnsiStringToUnicodeString			xRtlAnsiStringToUnicodeString;
	TRtlInitAnsiString						xRtlInitAnsiString;
	TRtlZeroMemory							xRtlZeroMemory;
	TRtlFreeUnicodeString					xRtlFreeUnicodeString;
	TRtlGetVersion							xRtlGetVersion;
	TRtlImageDirectoryEntryToData			xRtlImageDirectoryEntryToData;
	TRtlFormatCurrentUserKeyPath			xRtlFormatCurrentUserKeyPath;
	TReadProcessMemory						xReadProcessMemory;
	TWriteProcessMemory						xWriteProcessMemory;


	TRegCreateKeyExW						xRegCreateKeyExW;
	TRegSetValueExW							xRegSetValueExW;
	TRegSetValueExA							xRegSetValueExA;							
	TRegCloseKey							xRegCloseKey;
	TRegOpenKeyA							xRegOpenKeyA;
	TRegOpenKeyExA							xRegOpenKeyExA;
	TRegQueryValueExW						xRegQueryValueExW;
	TRegQueryValueExA						xRegQueryValueExA;

	TSizeofResource							xSizeofResource;
	TSleep									xSleep;
	TSetFilePointer							xSetFilePointer;

	TThread32First							xThread32First;
	TThread32Next							xThread32Next;

	TUnmapViewOfFile						xUnmapViewOfFile;
	TVirtualAllocEx							xVirtualAllocEx;	//没有填充地址
	TVirtualFreeEx							xVirtualFreeEx;		//暂时没填充地址
	TVirtualProtectEx						xVirtualProtectEx;	//暂时没填充地址
	TVirtualAlloc							xVirtualAlloc;
	TVirtualFree							xVirtualFree;
	TVirtualProtect							xVirtualProtect;

	TWideCharToMultiByte					xWideCharToMultiByte;
	TWriteFile								xWriteFile;
	TWinExec								xWinExec;

	TZwQuerySystemInformation				xZwQuerySystemInformation;
	TZwSuspendProcess						xZwSuspendProcess;
	TZwResumeProcess						xZwResumeProcess;
	/*---------kernel32 的导出函数声明结束------------*/


	//我们再次向这个结构体里面加东西的时候只有加在后面才能保证shellcode返回地址内容的兼容性
}TShellData,*PShellData;
#pragma pack(pop)



extern TShellData  ShellData;

typedef struct _SHELL_CODE_PARAM
{
	PVOID lpFileBase;
	LPVOID lpReserved;
	LPVOID lpProcName;
	LPVOID lpRunCmd;
}SHELL_CODE_PARAM, *PSHELL_CODE_PARAM;

typedef BOOL  (WINAPI *DLL_MAIN)( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved);

typedef VOID (WINAPI *pRunDll)(LPCWSTR pszRunCmd);


void  InitApiHashToStruct();
void  ShellCode_Start(PSHELL_CODE_PARAM pShellCodeParam);
DWORD ReleaseRebaseShellCode();
static void ShellCodeEntry(PSHELL_CODE_PARAM pShellCodeParam);
static BOOL GetRing3ApiAddr();



#ifdef __cplusplus
extern "C"
{
#endif
void	InitApiAddrToStruct();//如果需要和cpp混编这里是必不可少的

#ifdef __cplusplus 
}
#endif




//#define  PrintDebug
#ifdef	 PrintDebug
#define  print printf
#else
#define  print
#endif



//#define  HHL_DEBUG        
























//typedef   BOOL  (WINAPI *ProcDllMain)(HINSTANCE, DWORD, LPVOID);