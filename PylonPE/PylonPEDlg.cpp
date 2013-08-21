// PylonPEDlg.cpp : implementation file
//

#include "stdafx.h"
#include "PylonPE.h"
#include "PylonPEDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
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


// CPylonPEDlg dialog




CPylonPEDlg::CPylonPEDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPylonPEDlg::IDD, pParent)
	, m_strTargetName(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPylonPEDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_TARGET_NAME, m_strTargetName);
	DDX_Control(pDX, IDC_EDIT_RAW_DATA, m_editRawData);
	DDX_Control(pDX, IDC_EDIT_ANALYZED_DATA, m_editAnalyzedData);
	DDX_Control(pDX, IDC_LIST_SECTION, m_listSection);
}

BEGIN_MESSAGE_MAP(CPylonPEDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON_IMPORT, &CPylonPEDlg::OnBnClickedButtonImport)
	ON_LBN_SELCHANGE(IDC_LIST_SECTION, &CPylonPEDlg::OnLbnSelchangeListSection)
END_MESSAGE_MAP()


// CPylonPEDlg message handlers

BOOL CPylonPEDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CPylonPEDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CPylonPEDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CPylonPEDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CPylonPEDlg::OnBnClickedButtonImport()
{
	UpdateData(TRUE);
	m_strTargetName = L"E:\\WorkStation_TruckNet\\ThuNavStd\\Release\\Runtime\\ThuNav32d.exe";
	// TODO: Add your control notification handler code here
	CFileDialog fdlgSavePath( TRUE, NULL, L"", OFN_HIDEREADONLY, L"PE Files(*.exe)|*.exe||", NULL);
	fdlgSavePath.m_ofn.lpstrTitle = L"请输入导入路径并输入文件名";
	if( fdlgSavePath.DoModal() == IDOK )
	{
		m_strTargetName = fdlgSavePath.GetPathName();
		std::wstring fileName = m_strTargetName.GetBuffer(0);
		m_Analyzer.Analyze(fileName);
	}

	getSectionInfo();

	UpdateData(FALSE);
}

void CPylonPEDlg::getSectionInfo()
{
	m_listSection.ResetContent();
	m_AllSectionEx.clear();

	// dos header
	if (m_Analyzer.GetHasDosHeader() == true)
	{
		PESectionEx dosHeader;
		dosHeader.m_GetName = &PEAnalyzer::GetDosHeaderName;
		dosHeader.m_GetRD = &PEAnalyzer::GetDosHeaderRD;
		dosHeader.m_GetAD = &PEAnalyzer::GetDosHeaderAD;
		m_AllSectionEx.push_back(dosHeader);
	}

	// file header
	PESectionEx fileHeader;
	fileHeader.m_GetName = &PEAnalyzer::GetFileHeaderName;
	fileHeader.m_GetRD = &PEAnalyzer::GetFileHeaderRD;
	fileHeader.m_GetAD = &PEAnalyzer::GetFileHeaderAD;
	m_AllSectionEx.push_back(fileHeader);

	// optional header
	if (m_Analyzer.GetHasOptionalHeader() == true)
	{
		PESectionEx optionalHeader;
		optionalHeader.m_GetName = &PEAnalyzer::GetOptionalHeaderName;
		optionalHeader.m_GetRD = &PEAnalyzer::GetOptionalHeaderRD;
		optionalHeader.m_GetAD = &PEAnalyzer::GetOptionalHeaderAD;
		m_AllSectionEx.push_back(optionalHeader);
	}

	// section Directories
	if (m_Analyzer.GetHasSectionDirectories() == true)
	{
		PESectionEx sectionDirectories;
		sectionDirectories.m_GetName = &PEAnalyzer::GetSectionDirectoriesName;
		sectionDirectories.m_GetRD = &PEAnalyzer::GetSectionDirectoriesRD;
		sectionDirectories.m_GetAD = &PEAnalyzer::GetSectionDirectoriesAD;
		m_AllSectionEx.push_back(sectionDirectories);
	}

	// Import
	if (m_Analyzer.GetHasIAT() == true)
	{
		PESectionEx Import;
		Import.m_GetName = &PEAnalyzer::GetImportName;
		Import.m_GetRD = &PEAnalyzer::GetImportRD;
		Import.m_GetAD = &PEAnalyzer::GetImportAD;
		m_AllSectionEx.push_back(Import);
	}

	// IAT
	if (m_Analyzer.GetHasIAT() == true)
	{
		PESectionEx iat;
		iat.m_GetName = &PEAnalyzer::GetIATName;
		iat.m_GetRD = &PEAnalyzer::GetIATRD;
		iat.m_GetAD = &PEAnalyzer::GetIATAD;
		m_AllSectionEx.push_back(iat);
	}

	for (int idx=0; idx<m_AllSectionEx.size(); ++idx)
	{
		std::wstring dosHeaderName = (m_Analyzer.*m_AllSectionEx[idx].m_GetName)();
		m_listSection.InsertString(idx, dosHeaderName.c_str());
	}
}

void CPylonPEDlg::OnLbnSelchangeListSection()
{
	// TODO: Add your control notification handler code here
	int curSel = m_listSection.GetCurSel();
	std::wstring rdStr = (m_Analyzer.*m_AllSectionEx[curSel].m_GetRD)();
	std::wstring adStr = (m_Analyzer.*m_AllSectionEx[curSel].m_GetAD)();
	m_editRawData.SetWindowText( rdStr.c_str() );
	m_editAnalyzedData.SetWindowText( adStr.c_str() );
}
