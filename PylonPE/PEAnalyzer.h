#ifndef    _PE_ANALYZER_H_
#define    _PE_ANALYZER_H_

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "UtilTool.h"

// PE�ļ�����
// raw data��16�����ַ���
class PEAnalyzer
{
public:
	PEAnalyzer();
	~PEAnalyzer();

	void Analyze(const std::wstring& filename);

	// ��ȡdos header�������
	bool GetHasDosHeader() const;
	std::wstring GetDosHeaderName() const;
	std::wstring GetDosHeaderRD() const;
	std::wstring GetDosHeaderAD() const;

	// ��ȡfile header�������
	std::wstring GetFileHeaderName() const;
	std::wstring GetFileHeaderRD() const;
	std::wstring GetFileHeaderAD() const;

	// ��ȡoptional header�������
	bool GetHasOptionalHeader() const;
	std::wstring GetOptionalHeaderName() const;
	std::wstring GetOptionalHeaderRD() const;
	std::wstring GetOptionalHeaderAD() const;

	// ��ȡSectionDirectories�������
	bool GetHasSectionDirectories() const;
	std::wstring GetSectionDirectoriesName() const;
	std::wstring GetSectionDirectoriesRD() const;
	std::wstring GetSectionDirectoriesAD() const;

	// ��ȡimport�������
	bool GetHasImport() const;
	std::wstring GetImportName() const;
	std::wstring GetImportRD() const;
	std::wstring GetImportAD() const;

	// ��ȡIAT�������
	bool GetHasIAT() const;
	std::wstring GetIATName() const;
	std::wstring GetIATRD() const;
	std::wstring GetIATAD() const;

private:
	void analyzerDosHeader();
	void analyzerFileHeader();
	void analyzerOptionalHeader();
	void analyzerSectionDirectories();
	void analyzerImport();
	void analyzerIAT();
	int findSectionByVirtualAddr(DWORD virtualAddr, DWORD size) const;
	DWORD virtualAddr2RawPointer(DWORD virtualAddr, DWORD size) const;
	void readNullEndStringByVirtualAddr(DWORD virtualAddr, char* buf, DWORD bufBytes) const;
	std::wstring readWStringByVirtualAddr(DWORD virtualAddr) const;

private:
	std::wstring m_strFileName;
	FILE* m_File;

	IMAGE_DOS_HEADER m_DosHeader;
	IMAGE_FILE_HEADER m_FileHeader;
	IMAGE_OPTIONAL_HEADER m_OptionalHeader;
	std::vector< IMAGE_SECTION_HEADER > m_SectionDirectories;

	std::vector<IMAGE_IMPORT_DESCRIPTOR> m_Import;
	typedef std::vector< IMAGE_THUNK_DATA > DllINTs;
	std::vector< DllINTs > m_ImportINT;
	std::vector< DllINTs > m_ImportIAT;

	std::vector<IMAGE_THUNK_DATA> m_IAT;
};

#endif