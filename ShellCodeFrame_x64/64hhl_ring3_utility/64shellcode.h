#pragma once

#include "64nativeapi.h"


#pragma pack(push)
#pragma pack(1)
typedef struct _ShellData
{
	BOOL									bIsInitSucess;
	HMODULE									base_ker32;
	HMODULE									base_ntdll;
	HMODULE									base_psapi;
	HMODULE									base_advapi32;
	TCreateFileA							xCreateFileA;
	TCreateFileA							xCreateFileW;
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

	TDeleteFileA							xDeleteFileA;
	TDeleteFileW							xDeleteFileW;

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

	TUnmapViewOfFile						xUnmapViewOfFile;
	TVirtualAllocEx							xVirtualAllocEx;	
	TVirtualFreeEx							xVirtualFreeEx;		
	TVirtualProtectEx						xVirtualProtectEx;	
	TVirtualAlloc							xVirtualAlloc;
	TVirtualFree							xVirtualFree;
	TVirtualProtect							xVirtualProtect;

	TWideCharToMultiByte					xWideCharToMultiByte;
	TWriteFile								xWriteFile;
	TWinExec								xWinExec;

	TZwQuerySystemInformation				xZwQuerySystemInformation;


}TShellData,*PShellData;
#pragma pack(pop)
extern TShellData  ShellData;

typedef BOOL  (WINAPI *DLL_MAIN)( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved);

typedef VOID (WINAPI *pRunDll)(LPCWSTR pszRunCmd);

typedef struct _SHELL_CODE_PARAM
{
	PVOID lpFileBase;
	LPVOID lpReserved;
	LPVOID lpProcName;
	LPVOID lpRunCmd;
}SHELL_CODE_PARAM, *PSHELL_CODE_PARAM;



void  InitApiHashToStruct();
void ShellCode_Entry(PSHELL_CODE_PARAM pShellCodeParam);


extern void 			AlignRSPAndCallShEntry(PSHELL_CODE_PARAM pParam);
extern ULONG64          get_kernel32_peb_64();
extern ULONG64			get_ntdll_peb_64();
extern void				MyShellCodeFinalEnd();


static BOOL  GetRing3ApiAddr();


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