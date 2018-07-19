
// TestShellcodeDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"


// CTestShellcodeDlg 对话框
class CTestShellcodeDlg : public CDialog
{
// 构造
public:
	CTestShellcodeDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_TESTSHELLCODE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CRichEditCtrl m_reditShellcode;
	CEdit m_editProcessId;
	afx_msg void OnBnClickedButtonInject();
	afx_msg void OnBnClickedButtonShell();
	CEdit m_txtApiName;
	CEdit m_txtHashValue;
	afx_msg void OnBnClickedButtonCalchash();
	afx_msg void OnBnClickedButtonInjectDll();
	CEdit m_txtDllPath;
	afx_msg void OnBnClickedButtonLoadDll();
};
