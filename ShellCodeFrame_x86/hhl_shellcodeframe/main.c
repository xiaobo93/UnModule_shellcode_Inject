#include "shellcode.h"
#include "shellcode_ntapi_utility.h"
#include "nativeapi.h"


void main()
{

#ifdef  HHL_DEBUG
	SHELL_CODE_PARAM ShellCodeParam;
	FILE *fp;
	int nLength;
	UCHAR* pFileBase;
	wchar_t* lpReserved;
	char* lpProcName;
	wchar_t* lpRunCmd = NULL;

	fp = fopen("c:\\testdll.dll", "rb");
	
	if(fp)
	{
		nLength = filelength(fileno(fp));
		pFileBase = (char*)malloc(nLength+1);
		if(pFileBase)
		{
			memset(pFileBase, 0, nLength+1);
		}
		fread(pFileBase, nLength, 1, fp);
		fclose(fp);
		
	}
	else
	{
		return;
	}

	InitApiHashToStruct();

	ShellCodeParam.lpFileBase = pFileBase;

	lpReserved = (wchar_t*)malloc(MAX_PATH);
	memset(lpReserved, 0, MAX_PATH);
	wsprintf((LPSTR)lpReserved, L"Hello World!");
	ShellCodeParam.lpReserved = lpReserved;

	lpProcName = (char*)malloc(MAX_PATH);
	memset(lpProcName, 0, MAX_PATH);
	sprintf(lpProcName, "RunDll");
	ShellCodeParam.lpProcName = lpProcName;

	lpRunCmd = (wchar_t*)malloc(MAX_PATH);
	memset(lpRunCmd, 0, MAX_PATH);
	wsprintf(lpRunCmd, L"-a aaaaaaaaaaaa -u uuuuuuuuuuuuuu");
	ShellCodeParam.lpRunCmd = lpRunCmd;

	ShellCode_Start(ShellCodeParam);

	if(lpRunCmd)
		free(lpRunCmd);

	if(lpProcName)
		free(lpProcName);

	if(lpReserved)
		free(lpReserved);

	if(pFileBase)
		free(pFileBase);
#else
	InitApiHashToStruct();
#endif
}

