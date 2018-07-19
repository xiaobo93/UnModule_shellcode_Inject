
// TestShellcodeDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "TestShellcode.h"
#include "TestShellcodeDlg.h"
#include "ModuleLess.h"
#include "..\\ThreadLess\ThreadLess.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


UCHAR* g_ucShellCode;
int g_nShellCodeLength;

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CTestShellcodeDlg 对话框




CTestShellcodeDlg::CTestShellcodeDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CTestShellcodeDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CTestShellcodeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_RICHEDIT21_SHELLCODE, m_reditShellcode);
	DDX_Control(pDX, IDC_EDIT_PROCESS_ID, m_editProcessId);
	DDX_Control(pDX, IDC_EDIT_API, m_txtApiName);
	DDX_Control(pDX, IDC_EDIT_HASH, m_txtHashValue);
	DDX_Control(pDX, IDC_EDIT_DLL_PATH, m_txtDllPath);
}

BEGIN_MESSAGE_MAP(CTestShellcodeDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON_INJECT, &CTestShellcodeDlg::OnBnClickedButtonInject)
	ON_BN_CLICKED(IDC_BUTTON_SHELL, &CTestShellcodeDlg::OnBnClickedButtonShell)
	ON_BN_CLICKED(IDC_BUTTON_CALCHASH, &CTestShellcodeDlg::OnBnClickedButtonCalchash)
	ON_BN_CLICKED(IDC_BUTTON_INJECT_DLL, &CTestShellcodeDlg::OnBnClickedButtonInjectDll)
	ON_BN_CLICKED(IDC_BUTTON_LOAD_DLL, &CTestShellcodeDlg::OnBnClickedButtonLoadDll)
END_MESSAGE_MAP()

BOOL EnableDebugPrivilege()
{  
	HANDLE hToken;  
	LUID sedebugnameValue;  
	TOKEN_PRIVILEGES tkp;  
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{  
		return   FALSE;  
	}  
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))  
	{  
		CloseHandle(hToken);  
		return FALSE;  
	}  
	tkp.PrivilegeCount = 1;  
	tkp.Privileges[0].Luid = sedebugnameValue;  
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{  
		CloseHandle(hToken);  
		return FALSE;  
	}  
	return TRUE;  
}

// CTestShellcodeDlg 消息处理程序

BOOL CTestShellcodeDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	EnableDebugPrivilege();

	m_txtDllPath.SetWindowText(L"E:\\SVN\\WN58Soft\\58网维新软件\\网维项目\\ShellCodeFrame_x86\\Release\\TestDll.dll");
	CFile cf(L"c:\\GetRing3ApiAddr.bin", CFile::modeRead);
	g_nShellCodeLength = (int)cf.GetLength();
	
	g_ucShellCode = new UCHAR[g_nShellCodeLength];
	memset(g_ucShellCode, 0 , g_nShellCodeLength);
	cf.Read(g_ucShellCode, g_nShellCodeLength);
	cf.Close();

	CString strShellCode = L"";
	CString strTemp;
	for (int i = 0; i < g_nShellCodeLength; i++)
	{
		strTemp = strShellCode;
		strShellCode.Format(L"%s\\x%.2X", strTemp, g_ucShellCode[i]);
	}

	m_reditShellcode.SetWindowText(strShellCode);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CTestShellcodeDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CTestShellcodeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CTestShellcodeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BOOL InjectShellCode(unsigned char* ucShellCode, int nShellCodeLength, DWORD dwProcessId)
{
	SIZE_T				NumberOfByteWritten = 0;
	LPVOID				lpFileMem = NULL;
	LPVOID				lpShellCode = NULL;
	LPVOID				lpShellCodeParam = NULL;
	LPVOID				lpCommandLine = NULL;
	BOOL				bRet = FALSE;
	DWORD				dwShellCodeSize;

	dwShellCodeSize = nShellCodeLength;
	HANDLE hProcess = OpenProcess(0x1F0FFF, FALSE, dwProcessId);
	if ((hProcess == NULL) || (INVALID_HANDLE_VALUE == hProcess)){	return FALSE;	}

	lpShellCode = VirtualAllocEx(hProcess,NULL,dwShellCodeSize,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	if (lpShellCode == NULL)
	{
		goto FREEANDRETURN;
	}

	if (WriteProcessMemory(hProcess,(CHAR*)lpShellCode, ucShellCode, dwShellCodeSize,&NumberOfByteWritten) == FALSE)
	{
		goto FREEANDRETURN;
	}


	DWORD dwThreadID = 0;
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpShellCode, lpShellCodeParam, 0, &dwThreadID);
	if (hRemoteThread != NULL)
	{
		CloseHandle(hRemoteThread);
		bRet = TRUE;
	}
FREEANDRETURN:
	if(bRet == FALSE)
	{
		if(lpShellCode != NULL)
			VirtualFreeEx(hProcess,lpShellCode,dwShellCodeSize,MEM_RELEASE);
	}
	CloseHandle(hProcess);
	return bRet;
}

//************************************
// 函数名称:    ModuleLessLoad
// 函数说明：	内存中加载DLL
// 作    者：	刘二表
// 生成日期：	2017/05/13
// 参    数：	PVOID lpFileBase	DLL文件加载到内存基址
// 参    数：	SIZE_T ImageSize	DLL文件的大小
// 参    数：	wchar_t * szReserved	传递给DllMain的lpReserved参数
// 参    数：	char * szProcName	Dll导出函数名
// 参    数：	wchar_t * szRunCmd	传递给导出函数的参数
// 返 回 值：	void
//************************************
void ModuleLessLoad(PVOID lpFileBase,SIZE_T ImageSize, UCHAR* ucShellCode, int nShellCodeLength, wchar_t* szReserved, char* szProcName, wchar_t* szRunCmd)
{
	DWORD dwOldProtect, dwOldProtect1;
	
	VirtualProtect(lpFileBase, ImageSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	VirtualProtect(ucShellCode, nShellCodeLength, PAGE_EXECUTE_READWRITE, &dwOldProtect1);
	
	SHELL_CODE_PARAM ShellCodeParam;
	ShellCodeParam.lpFileBase = lpFileBase;
	ShellCodeParam.lpReserved = (PVOID)szReserved;
	ShellCodeParam.lpProcName = (LPVOID)szProcName;
	ShellCodeParam.lpRunCmd = (LPVOID)szRunCmd;

	_asm
	{
		pushad
		lea		eax, [ShellCodeParam]
		push	eax
		call	ucShellCode
		add		esp, 4
		popad
	}
	VirtualProtect(ucShellCode, nShellCodeLength, dwOldProtect1, &dwOldProtect1);
	VirtualProtect(lpFileBase, ImageSize, dwOldProtect, &dwOldProtect);
}

//************************************
// 函数名称:    ModuleLessInject
// 函数说明：	
// 作    者：	刘二表
// 生成日期：	2017/05/13
// 参    数：	DWORD dwProcessId	要注入进程的ID
// 参    数：	PVOID lpFileBase	DLL文件加载到内存基址
// 参    数：	SIZE_T ImageSize	DLL文件的大小
// 参    数：	wchar_t * szReserved	传递给DllMain的lpReserved参数
// 参    数：	char * szProcName	Dll导出函数名
// 参    数：	wchar_t * szRunCmd	传递给导出函数的参数
// 返 回 值：	BOOL	注入成功返回TRUE，否则返回FALSE
//************************************
BOOL ModuleLessInject(DWORD dwProcessId, PVOID lpFileBase, SIZE_T ImageSize, UCHAR* ucShellCode, int nShellCodeLength, wchar_t* szReserved, char* szProcName, wchar_t* szRunCmd)
{
	SIZE_T				NumberOfByteWritten = 0;
	LPVOID				lpFileMem = NULL;
	LPVOID				lpShellCode = NULL;
	LPVOID				lpShellCodeParam = NULL;
	LPVOID				lpReserved = NULL;
	LPVOID				lpProcName = NULL;
	LPVOID				lpRunCmd = NULL;
	BOOL				bRet = FALSE;
	SIZE_T ReservedLength = 0;
	SIZE_T ProcNameLength = 0;
	SIZE_T RunCmdLength = 0;
	SIZE_T ShellCodeParamLength = 0;
	
	HANDLE hProcess = OpenProcess(0x1F0FFF, FALSE, dwProcessId);
	if ((hProcess == NULL) || (INVALID_HANDLE_VALUE == hProcess)){	return FALSE;	}

	lpFileMem = VirtualAllocEx(hProcess, NULL, ImageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpFileMem == NULL)
	{
		goto FREEANDRETURN;
	}
	if (WriteProcessMemory(hProcess,lpFileMem,lpFileBase,ImageSize,&NumberOfByteWritten) == FALSE)
	{
		goto FREEANDRETURN;
	}

	if(szReserved != NULL)
	{
		ReservedLength = (wcslen(szReserved) + 1)*sizeof(wchar_t);
		lpReserved = VirtualAllocEx(hProcess, NULL ,ReservedLength, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpReserved == NULL)
		{
			goto FREEANDRETURN;
		}
		if (WriteProcessMemory(hProcess, lpReserved, szReserved, ReservedLength, &NumberOfByteWritten) == FALSE)
		{
			goto FREEANDRETURN;
		}
	}

	if(szProcName != NULL)
	{
		ProcNameLength = (strlen(szProcName) + 1)*sizeof(char);
		lpProcName = VirtualAllocEx(hProcess, NULL ,ProcNameLength, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpProcName == NULL)
		{
			goto FREEANDRETURN;
		}
		if (WriteProcessMemory(hProcess, lpProcName, szProcName, ProcNameLength, &NumberOfByteWritten) == FALSE)
		{
			goto FREEANDRETURN;
		}
	}
	
	if(szRunCmd != NULL)
	{
		RunCmdLength = (wcslen(szRunCmd) + 1)*sizeof(wchar_t);
		lpRunCmd = VirtualAllocEx(hProcess, NULL ,RunCmdLength, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpRunCmd == NULL)
		{
			goto FREEANDRETURN;
		}
		if (WriteProcessMemory(hProcess, lpRunCmd, szRunCmd, RunCmdLength, &NumberOfByteWritten) == FALSE)
		{
			goto FREEANDRETURN;
		}
	}

	ShellCodeParamLength = sizeof(SHELL_CODE_PARAM);
	lpShellCodeParam = VirtualAllocEx(hProcess, NULL, ShellCodeParamLength, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpShellCodeParam == NULL)
	{
		goto FREEANDRETURN;
	}
	if (WriteProcessMemory(hProcess, lpShellCodeParam, &lpFileMem, sizeof(LPVOID), &NumberOfByteWritten) == FALSE
		|| WriteProcessMemory(hProcess, (LPVOID)((BYTE*)lpShellCodeParam + sizeof(LPVOID)*1), &lpReserved, sizeof(LPVOID), &NumberOfByteWritten) == FALSE
		|| WriteProcessMemory(hProcess, (LPVOID)((BYTE*)lpShellCodeParam + sizeof(LPVOID)*2), &lpProcName, sizeof(LPVOID), &NumberOfByteWritten) == FALSE
		|| WriteProcessMemory(hProcess, (LPVOID)((BYTE*)lpShellCodeParam + sizeof(LPVOID)*3), &lpRunCmd, sizeof(LPVOID), &NumberOfByteWritten) == FALSE)
	{
		goto FREEANDRETURN;
	}

	lpShellCode = VirtualAllocEx(hProcess, NULL, nShellCodeLength, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpShellCode == NULL)
	{
		goto FREEANDRETURN;
	}

	if (WriteProcessMemory(hProcess, (CHAR*)lpShellCode, ucShellCode, nShellCodeLength, &NumberOfByteWritten) == FALSE)
	{
		goto FREEANDRETURN;
	}

	
	DWORD dwThreadID = 0;
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpShellCode, lpShellCodeParam, 0, &dwThreadID);
	if (hRemoteThread != NULL)
	{
		CloseHandle(hRemoteThread);
		bRet = TRUE;
	}
FREEANDRETURN:
	if(bRet == FALSE)
	{
		if(lpFileMem != NULL)
			VirtualFreeEx(hProcess,lpFileMem,ImageSize,MEM_RELEASE);
		if(lpReserved != NULL)
			VirtualFreeEx(hProcess,lpReserved,ReservedLength,MEM_RELEASE);
		if(lpProcName != NULL)
			VirtualFreeEx(hProcess,lpProcName,ProcNameLength,MEM_RELEASE);
		if(lpRunCmd != NULL)
			VirtualFreeEx(hProcess,lpRunCmd,RunCmdLength,MEM_RELEASE);
		if(lpShellCodeParam != NULL)
			VirtualFreeEx(hProcess,lpShellCodeParam,ShellCodeParamLength,MEM_RELEASE);
		if(lpShellCode != NULL)
			VirtualFreeEx(hProcess,lpShellCode, nShellCodeLength,MEM_RELEASE);
	}
	CloseHandle(hProcess);
	return bRet;
}

int GetByteNums(CString strBytes)
{
	int nStart = 0;
	int cnt = 0;
	nStart = strBytes.Find(_T("\\x"), nStart);
	while(nStart >= 0)
	{
		nStart += 2;
		cnt++;
		nStart = strBytes.Find(_T("\\x"), nStart);
	}
	return cnt;
}



DWORD HashKey(char *key)
{
	DWORD nHash = 0;
	while (*key)
	{
		nHash = (nHash<<5) + nHash + *key++;
	}
	return nHash;
}

// 计算API的Hash值
void CTestShellcodeDlg::OnBnClickedButtonCalchash()
{
	CString strApiName;
	CStringA strApiNameA;
	DWORD dwHashValue;

	m_txtApiName.GetWindowText(strApiName);
	strApiNameA = strApiName;
	char* szApiName = strApiNameA.GetBuffer(0);
	dwHashValue = HashKey(szApiName);
	strApiNameA.ReleaseBuffer();
	strApiName.Format(L"0x%x", dwHashValue);
	m_txtHashValue.SetWindowText(strApiName);
}

// 注入并执行
void CTestShellcodeDlg::OnBnClickedButtonInject()
{
	CString strShellcode;
	CString strProcessId;
	CString strHex;
	DWORD dwProcessId;

	m_editProcessId.GetWindowText(strProcessId);
	if(strProcessId == _T(""))
		return;
	dwProcessId = _wtoi(strProcessId.GetBuffer(0));
	InjectShellCode(g_ucShellCode, g_nShellCodeLength, dwProcessId);
}

// 直接执行
void CTestShellcodeDlg::OnBnClickedButtonShell()
{
	CString strShellcode;
	CString strProcessId;
	CString strHex;
	DWORD dwOldProtect;

	VirtualProtect(g_ucShellCode, g_nShellCodeLength, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	_asm
	{
		pushad
			call g_ucShellCode
			popad
	}
	VirtualProtect(g_ucShellCode, g_nShellCodeLength, dwOldProtect, &dwOldProtect);
}

// 加载DLL
void CTestShellcodeDlg::OnBnClickedButtonLoadDll()
{
	CString strShellcode;
	CString strProcessId;
	CString strDllPath;
	CString strHex;
	DWORD dwProcessId;

	dwProcessId = _wtoi(strProcessId.GetBuffer(0));

	m_txtDllPath.GetWindowText(strDllPath);
	if(strDllPath == _T(""))
		return;

	if(!PathFileExists(strDllPath))
		return;

	UCHAR *ucDllHex;
	int nDllHexLength;

	CFile cf(strDllPath, CFile::modeRead);
	nDllHexLength = (int)cf.GetLength();
	ucDllHex = new UCHAR[nDllHexLength];
	memset(ucDllHex, 0, nDllHexLength);
	cf.Read(ucDllHex,nDllHexLength);
	//ModuleLessLoad(ucDllHex, nDllHexLength, g_ucShellCode, g_nShellCodeLength, L"Hello World!", "RunDll", L"- a aaaaaaaaa -u uuuuuuuuuuuuuu");
	CModuleLess::ModuleLessLoad(ucDllHex, nDllHexLength, L"Hello World!", "RunDll", L"- a aaaaaaaaa -u uuuuuuuuuuuuuu");
	delete[] ucDllHex;
}
DWORD FirstThreadRoutine()
{
	CString strTemp;
	strTemp.Format(L"FirstThreadRoutine Thread Id is %d\r\n", GetCurrentThreadId());
	OutputDebugString(strTemp);
	int cnt = 0;
	while(TRUE)
	{
		strTemp.Format(L"FirstThreadRoutine cnt Id is %d\r\n", cnt++);
		OutputDebugString(strTemp);
		Sleep(5000);
	}
	return 0;
}
// 注入DLL
void CTestShellcodeDlg::OnBnClickedButtonInjectDll()
{
	DWORD aaa = PROCESS_ALL_ACCESS;
	CString strShellcode;
	CString strProcessId;
	CString strDllPath;
	CString strHex;
	DWORD dwProcessId;
	
	m_editProcessId.GetWindowText(strProcessId);
	if(strProcessId == _T(""))
		return;
	dwProcessId = _wtoi(strProcessId.GetBuffer(0));

	m_txtDllPath.GetWindowText(strDllPath);
	if(strDllPath == _T(""))
		return;

	if(!PathFileExists(strDllPath))
		return;

	UCHAR *ucDllHex;
	int nDllHexLength;
	
	CFile cf(strDllPath, CFile::modeRead);
	nDllHexLength = (int)cf.GetLength();
	ucDllHex = new UCHAR[nDllHexLength];
	memset(ucDllHex, 0, nDllHexLength);
	cf.Read(ucDllHex,nDllHexLength);
	//ModuleLessInject(dwProcessId, ucDllHex, nDllHexLength, g_ucShellCode, g_nShellCodeLength, L"Hello World!", "RunDll", L"- a aaaaaaaaa -u uuuuuuuuuuuuuu");
	CModuleLess::ModuleLessInject(dwProcessId, ucDllHex, nDllHexLength, L"Hello World!", "RunDll", L"- a aaaaaaaaa -u uuuuuuuuuuuuuu");

	//CModuleLess::Wow64ModuleLessInjectToX64(dwProcessId, ucDllHex, nDllHexLength, L"Hello World!", "RunDll", L"- a aaaaaaaaa -u uuuuuuuuuuuuuu");
	delete[] ucDllHex;
}


