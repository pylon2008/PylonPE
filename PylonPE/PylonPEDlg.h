// PylonPEDlg.h : header file
//

#pragma once
#include "afxwin.h"
#include "PEAnalyzer.h"
#include <vector>

typedef std::wstring (PEAnalyzer::*GetFun)() const;
struct PESectionEx
{
	GetFun m_GetName;
	GetFun m_GetRD;
	GetFun m_GetAD;
};

// CPylonPEDlg dialog
class CPylonPEDlg : public CDialog
{
// Construction
public:
	CPylonPEDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_PYLONPE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

private:
	void getSectionInfo();

private:
	CString m_strTargetName;
	CEdit m_editRawData;
	CEdit m_editAnalyzedData;
	CListBox m_listSection;
	PEAnalyzer m_Analyzer;
	std::vector<PESectionEx> m_AllSectionEx;

public:
	afx_msg void OnBnClickedButtonImport();
	afx_msg void OnLbnSelchangeListSection();
};
