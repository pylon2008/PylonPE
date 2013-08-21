#include "PEAnalyzer.h"
#include <vector>
#include <time.h>
//http://service.bj.10086.cn/autumn/xyyx2013/index.html
PEAnalyzer::PEAnalyzer()
{
	m_strFileName = L"";
}

PEAnalyzer::~PEAnalyzer()
{
	;
}

void PEAnalyzer::Analyze(const std::wstring& filename)
{
	m_strFileName = filename;
	_wfopen_s(&m_File, m_strFileName.c_str(), L"r+b");

	analyzerDosHeader();
	analyzerFileHeader();
	analyzerOptionalHeader();
	analyzerSectionDirectories();
	analyzerImport();
	analyzerIAT();
}

void PEAnalyzer::analyzerDosHeader()
{
	fseek(m_File, 0, SEEK_SET);
	fread(&m_DosHeader, 1, sizeof(IMAGE_DOS_HEADER), m_File);
}

void PEAnalyzer::analyzerFileHeader()
{
	DWORD imageNtSignature = 0;
	fseek(m_File, m_DosHeader.e_lfanew, SEEK_SET);
	fread(&imageNtSignature, 1, sizeof(imageNtSignature), m_File);
	if (imageNtSignature == 0x00004550)
	{
		fseek(m_File, m_DosHeader.e_lfanew+sizeof(imageNtSignature), SEEK_SET);
		fread(&m_FileHeader, 1, sizeof(m_FileHeader), m_File);
	}
	else
	{
		memset(&m_FileHeader, 0, sizeof(m_FileHeader));
	}
}

void PEAnalyzer::analyzerOptionalHeader()
{
	int bytes = sizeof(m_OptionalHeader);
	if (bytes == m_FileHeader.SizeOfOptionalHeader)
	{
		fseek(m_File, m_DosHeader.e_lfanew+sizeof(DWORD)+sizeof(m_FileHeader), SEEK_SET);
		fread(&m_OptionalHeader, 1, sizeof(m_OptionalHeader), m_File);
	}
	else
	{
		memset(&m_OptionalHeader, 0, sizeof(m_OptionalHeader));
	}
}

void PEAnalyzer::analyzerSectionDirectories()
{
	m_SectionDirectories.resize( m_FileHeader.NumberOfSections );
	if (m_FileHeader.NumberOfSections > 0)
	{
		fseek(m_File, m_DosHeader.e_lfanew+sizeof(DWORD)+sizeof(m_FileHeader)+m_FileHeader.SizeOfOptionalHeader, SEEK_SET);
		fread(&m_SectionDirectories[0], 1, m_SectionDirectories.size()*sizeof(IMAGE_SECTION_HEADER), m_File);
	}
}

int PEAnalyzer::findSectionByVirtualAddr(DWORD virtualAddr, DWORD size) const
{
	int sectionDirectoryIdx = 0xffffffff;
	for (int idx=0; idx<m_SectionDirectories.size(); ++idx)
	{
		if (virtualAddr>=m_SectionDirectories[idx].VirtualAddress 
			&& virtualAddr+size<=m_SectionDirectories[idx].VirtualAddress+m_SectionDirectories[idx].Misc.VirtualSize)
		{
			sectionDirectoryIdx = idx;
			break;
		}
	}
	return sectionDirectoryIdx;
}

DWORD PEAnalyzer::virtualAddr2RawPointer(DWORD virtualAddr, DWORD size) const
{
	DWORD pointer = 0xffffffff;
	int sectionDirectoryIdx = findSectionByVirtualAddr(virtualAddr, size);
	if (sectionDirectoryIdx == 0xffffffff)
	{
		return pointer;
	}
	pointer = m_SectionDirectories[sectionDirectoryIdx].PointerToRawData + (virtualAddr-m_SectionDirectories[sectionDirectoryIdx].VirtualAddress);
	return pointer;
}

void PEAnalyzer::analyzerImport()
{
	DWORD virtualAddr = m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD size = m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	int sectionDirectoryIdx = findSectionByVirtualAddr(virtualAddr, size);

	if (sectionDirectoryIdx<0 || sectionDirectoryIdx>=m_SectionDirectories.size())
	{
		throw "can not find the virtual import";
	}
	if (m_SectionDirectories[sectionDirectoryIdx].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA == 0
		||m_SectionDirectories[sectionDirectoryIdx].Characteristics & IMAGE_SCN_MEM_READ == 0)
	{
		throw "import Characteristics is not right";
	}

	m_Import.resize( size/sizeof(IMAGE_IMPORT_DESCRIPTOR) );
	int seekSize = m_SectionDirectories[sectionDirectoryIdx].PointerToRawData + (virtualAddr-m_SectionDirectories[sectionDirectoryIdx].VirtualAddress);
	fseek(m_File, seekSize, SEEK_SET);
	fread(&m_Import[0], 1, m_Import.size()*sizeof(IMAGE_IMPORT_DESCRIPTOR), m_File);

	IMAGE_IMPORT_DESCRIPTOR nullImport;
	memset(&nullImport, 0, sizeof(nullImport));
	int cmp = memcmp(&m_Import[m_Import.size()-1], &nullImport, sizeof(nullImport));
	if (cmp != 0)
	{
		throw "import descriptor last is not 00000000";
	}

	// GET INT
	for (int idx=0; idx<m_Import.size()-1; ++idx)
	{
		DllINTs ints;
		ints.reserve(1024);
		DWORD OriginalFirstThunk = m_Import[idx].OriginalFirstThunk;
		DWORD seekSize = virtualAddr2RawPointer(OriginalFirstThunk, 4);
		while( true)
		{
			IMAGE_THUNK_DATA data;
			fseek(m_File, seekSize, SEEK_SET);
			fread(&data, 1, sizeof(data), m_File);
			ints.push_back(data);
			if (data.u1.AddressOfData == 0)
			{
				break;
			}
			else
			{
				seekSize += sizeof(data);
			}
		}
		m_ImportINT.push_back(ints);
	}

	// GET IAT
	for (int idx=0; idx<m_Import.size()-1; ++idx)
	{
		DllINTs ints;
		ints.reserve(1024);
		DWORD FirstThunk = m_Import[idx].FirstThunk;
		DWORD seekSize = virtualAddr2RawPointer(FirstThunk, 4);
		while( true)
		{
			IMAGE_THUNK_DATA data;
			fseek(m_File, seekSize, SEEK_SET);
			fread(&data, 1, sizeof(data), m_File);
			ints.push_back(data);
			if (data.u1.AddressOfData == 0)
			{
				break;
			}
			else
			{
				seekSize += sizeof(data);
			}
		}
		m_ImportIAT.push_back(ints);
	}

	if (m_ImportINT.size() != m_ImportIAT.size())
	{
		throw "import INT size is not equal import IAT size";
	}

	for (int idx=0; idx<m_ImportIAT.size()-1; ++idx)
	{
		if (m_ImportIAT[idx].size() != m_ImportINT[idx].size())
		{
			throw "import INT size is not equal import IAT size inner";
		}
	}
}

void PEAnalyzer::analyzerIAT()
{
	DWORD virtualAddr = m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	DWORD size = m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
	int sectionDirectoryIdx = findSectionByVirtualAddr(virtualAddr, size);

	if (sectionDirectoryIdx<0 || sectionDirectoryIdx>=m_SectionDirectories.size())
	{
		return;
	}
	if (m_SectionDirectories[sectionDirectoryIdx].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA == 0
		||m_SectionDirectories[sectionDirectoryIdx].Characteristics & IMAGE_SCN_MEM_READ == 0)
	{
		return;
	}

	m_IAT.resize(size/sizeof(IMAGE_THUNK_DATA));
	int seekSize = m_SectionDirectories[sectionDirectoryIdx].PointerToRawData + (virtualAddr-m_SectionDirectories[sectionDirectoryIdx].VirtualAddress);
	fseek(m_File, seekSize, SEEK_SET);
	fread(&m_IAT[0], 1, m_IAT.size()*sizeof(IMAGE_THUNK_DATA), m_File);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool PEAnalyzer::GetHasDosHeader() const
{
	return m_DosHeader.e_magic == 0x5a4d;
}

std::wstring PEAnalyzer::GetDosHeaderName() const
{
	std::wstring hexString = L"DOSHeader";
	return hexString;
}

std::wstring PEAnalyzer::GetDosHeaderRD() const
{
	return Buf2WHexString((const char*)&m_DosHeader, sizeof(m_DosHeader));
}

std::wstring PEAnalyzer::GetDosHeaderAD() const
{
	wchar_t wbuf[10240] = {0};
	swprintf(wbuf, L"e_magic: %d\r\n\
e_cblp: %d\r\n\
e_cp: %d\r\n\
e_crlc: %d\r\n\
e_cparhdr: %d\r\n\
e_minalloc: %d\r\n\
e_maxalloc: %d\r\n\
e_ss: %d\r\n\
e_sp: %d\r\n\
e_csum: %d\r\n\
e_ip: %d\r\n\
e_cs: %d\r\n\
e_lfarlc: %d\r\n\
e_ovno: %d\r\n\
e_res: %d %d %d %d\r\n\
e_oemid: %d\r\n\
e_oeminfo: %d\r\n\
e_res2: %d %d %d %d %d %d %d %d %d %d\r\n\
e_lfanew: %d\
		", 
		m_DosHeader.e_magic, 
		m_DosHeader.e_cblp, 
		m_DosHeader.e_cp,
		m_DosHeader.e_crlc, 
		m_DosHeader.e_cparhdr, 
		m_DosHeader.e_minalloc, 
		m_DosHeader.e_maxalloc,
		m_DosHeader.e_ss, 
		m_DosHeader.e_sp, 
		m_DosHeader.e_csum, 
		m_DosHeader.e_ip,
		m_DosHeader.e_cs, 
		m_DosHeader.e_lfarlc, 
		m_DosHeader.e_ovno,
		m_DosHeader.e_res[0], m_DosHeader.e_res[1], m_DosHeader.e_res[2], m_DosHeader.e_res[3], 
		m_DosHeader.e_oemid, 
		m_DosHeader.e_oeminfo,
		m_DosHeader.e_res2[0],m_DosHeader.e_res2[1],m_DosHeader.e_res2[2],m_DosHeader.e_res2[3],
		m_DosHeader.e_res2[4],m_DosHeader.e_res2[5],m_DosHeader.e_res2[6],m_DosHeader.e_res2[7],
		m_DosHeader.e_res2[8],m_DosHeader.e_res2[9],
		m_DosHeader.e_lfanew);

	std::wstring hexString = wbuf;
	return hexString;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::wstring PEAnalyzer::GetFileHeaderName() const
{
	std::wstring hexString = L"FileHeader";
	return hexString;
}

std::wstring PEAnalyzer::GetFileHeaderRD() const
{
	return Buf2WHexString((const char*)&m_FileHeader, sizeof(m_FileHeader));
}

std::wstring PEAnalyzer::GetFileHeaderAD() const
{
	// get machine name
	struct MachineType 
	{
		WORD m_MachineId;
		std::wstring m_MachineName;
	};
	MachineType allMachine[] = {
		{IMAGE_FILE_MACHINE_I386, L"Intel 386"},
		{IMAGE_FILE_MACHINE_R3000, L"MIPS little-endian, 0x160 big-endian"},
		{IMAGE_FILE_MACHINE_R4000, L"IMAGE_FILE_MACHINE_R10000"},
		{IMAGE_FILE_MACHINE_WCEMIPSV2, L"MIPS little-endian WCE v2"},
		{IMAGE_FILE_MACHINE_ALPHA, L"Alpha_AXP"},
		{IMAGE_FILE_MACHINE_SH3, L"SH3 little-endian"},
		{IMAGE_FILE_MACHINE_SH3DSP, L"IMAGE_FILE_MACHINE_SH3DSP"},
		{IMAGE_FILE_MACHINE_SH3E, L"SH3E little-endian"},
		{IMAGE_FILE_MACHINE_SH4, L"SH4 little-endian"},
		{IMAGE_FILE_MACHINE_SH5, L"SH5"},
		{IMAGE_FILE_MACHINE_ARM, L"ARM Little-Endian"},
		{IMAGE_FILE_MACHINE_THUMB, L"IMAGE_FILE_MACHINE_THUMB"},
		{IMAGE_FILE_MACHINE_AM33, L"IMAGE_FILE_MACHINE_AM33"},
		{IMAGE_FILE_MACHINE_POWERPC, L"IBM PowerPC Little-Endian"},
		{IMAGE_FILE_MACHINE_POWERPCFP, L"IMAGE_FILE_MACHINE_POWERPCFP"},
		{IMAGE_FILE_MACHINE_IA64, L"Intel 64"},
		{IMAGE_FILE_MACHINE_MIPS16, L"MIPS"},
		{IMAGE_FILE_MACHINE_ALPHA64, L"ALPHA64"},
		{IMAGE_FILE_MACHINE_MIPSFPU, L"MIPS:IMAGE_FILE_MACHINE_MIPSFPU"},
		{IMAGE_FILE_MACHINE_MIPSFPU16, L"MIPS:IMAGE_FILE_MACHINE_MIPSFPU16"},
		{IMAGE_FILE_MACHINE_AXP64, L"ALPHA64:IMAGE_FILE_MACHINE_AXP64"},
		{IMAGE_FILE_MACHINE_TRICORE, L"Infineon"},
		{IMAGE_FILE_MACHINE_CEF, L"IMAGE_FILE_MACHINE_CEF"},
		{IMAGE_FILE_MACHINE_EBC, L"EFI Byte Code"},
		{IMAGE_FILE_MACHINE_AMD64, L"AMD64 (K8)"},
		{IMAGE_FILE_MACHINE_M32R, L"M32R little-endian"},
		{IMAGE_FILE_MACHINE_CEE, L"IMAGE_FILE_MACHINE_CEE"},
	};
	std::wstring machineName = L"UnKnow";
	for (int idx=0; idx<sizeof(allMachine)/sizeof(MachineType); ++idx)
	{
		if (allMachine[idx].m_MachineId == m_FileHeader.Machine)
		{
			machineName = allMachine[idx].m_MachineName;
			break;
		}
	}

	// get time
	time_t time = 0;
	memcpy(&time, &m_FileHeader.TimeDateStamp, sizeof(m_FileHeader.TimeDateStamp));
	std::wstring strTime = _wasctime(gmtime(&time));

	wchar_t wbuf[10240] = {0};
	swprintf(wbuf, L"Machine: %d, %s\r\n\
NumberOfSections: %d\r\n\
TimeDateStamp: %d, %s\r\n\
PointerToSymbolTable: %d\r\n\
NumberOfSymbols: %d\r\n\
SizeOfOptionalHeader: %d\r\n\
Characteristics: %d\
", 
m_FileHeader.Machine, machineName.c_str(),
m_FileHeader.NumberOfSections,
m_FileHeader.TimeDateStamp, strTime.c_str(),
m_FileHeader.PointerToSymbolTable,
m_FileHeader.NumberOfSymbols,
m_FileHeader.SizeOfOptionalHeader,
m_FileHeader.Characteristics);

	std::wstring hexString = wbuf;
	return hexString;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool PEAnalyzer::GetHasOptionalHeader() const
{
	return m_FileHeader.SizeOfOptionalHeader > 0;
}

std::wstring PEAnalyzer::GetOptionalHeaderName() const
{
	std::wstring hexString = L"OptionalHeader";
	return hexString;
}

std::wstring PEAnalyzer::GetOptionalHeaderRD() const
{
	return Buf2WHexString((const char*)&m_OptionalHeader, sizeof(m_OptionalHeader));
}

std::wstring PEAnalyzer::GetOptionalHeaderAD() const
{
	wchar_t wbuf[10240] = {0};
	swprintf(wbuf, L"\
Magic: %d\r\n\
MajorLinkerVersion: %d\r\n\
MinorLinkerVersion: %d\r\n\
SizeOfCode: %d\r\n\
SizeOfInitializedData: %d\r\n\
SizeOfUninitializedData: %d\r\n\
AddressOfEntryPoint: %d\r\n\
BaseOfCode: %d\r\n\
BaseOfData: %d\r\n\
ImageBase: %d\r\n\
SectionAlignment: %d\r\n\
FileAlignment: %d\r\n\
MajorOperatingSystemVersion: %d\r\n\
MinorOperatingSystemVersion: %d\r\n\
MajorImageVersion: %d\r\n\
MinorImageVersion: %d\r\n\
MajorSubsystemVersion: %d\r\n\
MinorSubsystemVersion: %d\r\n\
Win32VersionValue: %d\r\n\
SizeOfImage: %d\r\n\
SizeOfHeaders: %d\r\n\
CheckSum: %d\r\n\
Subsystem: %d\r\n\
DllCharacteristics: %d\r\n\
SizeOfStackReserve: %d\r\n\
SizeOfStackCommit: %d\r\n\
SizeOfHeapReserve: %d\r\n\
SizeOfHeapCommit: %d\r\n\
LoaderFlags: %d\r\n\
NumberOfRvaAndSizes: %d\r\n\
DataDirectory: \r\n\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
\t%d, %d\r\n\
					", 
					m_OptionalHeader.Magic,
					m_OptionalHeader.MajorLinkerVersion,
					m_OptionalHeader.MinorLinkerVersion,
					m_OptionalHeader.SizeOfCode,
					m_OptionalHeader.SizeOfInitializedData,
					m_OptionalHeader.SizeOfUninitializedData,
					m_OptionalHeader.AddressOfEntryPoint,
					m_OptionalHeader.BaseOfCode,
					m_OptionalHeader.BaseOfData,
					m_OptionalHeader.ImageBase,
					m_OptionalHeader.SectionAlignment,
					m_OptionalHeader.FileAlignment,
					m_OptionalHeader.MajorOperatingSystemVersion,
					m_OptionalHeader.MinorOperatingSystemVersion,
					m_OptionalHeader.MajorImageVersion,
					m_OptionalHeader.MinorImageVersion,
					m_OptionalHeader.MajorSubsystemVersion,
					m_OptionalHeader.MinorSubsystemVersion,
					m_OptionalHeader.Win32VersionValue,
					m_OptionalHeader.SizeOfImage,
					m_OptionalHeader.SizeOfHeaders,
					m_OptionalHeader.CheckSum,
					m_OptionalHeader.Subsystem,
					m_OptionalHeader.DllCharacteristics,
					m_OptionalHeader.SizeOfStackReserve,
					m_OptionalHeader.SizeOfStackCommit,
					m_OptionalHeader.SizeOfHeapReserve,
					m_OptionalHeader.SizeOfHeapCommit,
					m_OptionalHeader.LoaderFlags,
					m_OptionalHeader.NumberOfRvaAndSizes,
					m_OptionalHeader.DataDirectory[0].VirtualAddress, m_OptionalHeader.DataDirectory[0].Size,
					m_OptionalHeader.DataDirectory[1].VirtualAddress, m_OptionalHeader.DataDirectory[1].Size,
					m_OptionalHeader.DataDirectory[2].VirtualAddress, m_OptionalHeader.DataDirectory[2].Size,
					m_OptionalHeader.DataDirectory[3].VirtualAddress, m_OptionalHeader.DataDirectory[3].Size,
					m_OptionalHeader.DataDirectory[4].VirtualAddress, m_OptionalHeader.DataDirectory[4].Size,
					m_OptionalHeader.DataDirectory[5].VirtualAddress, m_OptionalHeader.DataDirectory[5].Size,
					m_OptionalHeader.DataDirectory[6].VirtualAddress, m_OptionalHeader.DataDirectory[6].Size,
					m_OptionalHeader.DataDirectory[7].VirtualAddress, m_OptionalHeader.DataDirectory[7].Size,
					m_OptionalHeader.DataDirectory[8].VirtualAddress, m_OptionalHeader.DataDirectory[8].Size,
					m_OptionalHeader.DataDirectory[9].VirtualAddress, m_OptionalHeader.DataDirectory[9].Size,
					m_OptionalHeader.DataDirectory[10].VirtualAddress, m_OptionalHeader.DataDirectory[10].Size,
					m_OptionalHeader.DataDirectory[11].VirtualAddress, m_OptionalHeader.DataDirectory[11].Size,
					m_OptionalHeader.DataDirectory[12].VirtualAddress, m_OptionalHeader.DataDirectory[12].Size,
					m_OptionalHeader.DataDirectory[13].VirtualAddress, m_OptionalHeader.DataDirectory[13].Size,
					m_OptionalHeader.DataDirectory[14].VirtualAddress, m_OptionalHeader.DataDirectory[14].Size,
					m_OptionalHeader.DataDirectory[15].VirtualAddress, m_OptionalHeader.DataDirectory[15].Size
					);

	std::wstring hexString = wbuf;
	return hexString;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool PEAnalyzer::GetHasSectionDirectories() const
{
	return m_SectionDirectories.size()>0;
}

std::wstring PEAnalyzer::GetSectionDirectoriesName() const
{
	std::wstring hexString = L"SectionDirectories";
	return hexString;
}

std::wstring PEAnalyzer::GetSectionDirectoriesRD() const
{
	return Buf2WHexString((const char*)&m_SectionDirectories[0], m_SectionDirectories.size()*sizeof(IMAGE_SECTION_HEADER));
}

// IMAGE_SCN_CNT_CODE
std::wstring PEAnalyzer::GetSectionDirectoriesAD() const
{
/*
Name: %s,\
VirtualAddress: %d,\
SizeOfRawData: %d,\
PointerToRawData: %d,\
PointerToRelocations: %d,\
PointerToLinenumbers: %d,\
NumberOfRelocations: %d,\
NumberOfLinenumbers: %d,\
Characteristics: %d,\
*/
	wchar_t wbuf[10240] = {0};
	swprintf(wbuf, L"NumberOfSections: %d\r\n", m_SectionDirectories.size());
	swprintf(wbuf+wcslen(wbuf), L"%s\r\n", L"Name\
\tMisc\
\tVirtualAddress\
\tSizeOfRawData\
\tPointerToRawData\
\tPointerToRelocations\
\tPointerToLinenumbers\
\tNumberOfRelocations\
\tNumberOfLinenumbers\
\tCharacteristics\
											\r\n");
	for (int idx=0; idx<m_SectionDirectories.size(); ++idx)
	{
		wchar_t nameBuf[16] = {0};
		ToUnicode(nameBuf, (const char*)m_SectionDirectories[idx].Name, sizeof(nameBuf));
		swprintf(wbuf+wcslen(wbuf), L"\
%s\t\
%d\t\t\
%d\t\t\
%d\t\t\
%d\t\t\
%d\t\t\
%d\t\t\t\
%d\t\t\t\
%d\t\t\t\
%u\t\t\t\
									 \r\n", 
									 nameBuf,
									 m_SectionDirectories[idx].Misc,
									 m_SectionDirectories[idx].VirtualAddress,
									 m_SectionDirectories[idx].SizeOfRawData,
									 m_SectionDirectories[idx].PointerToRawData,
									 m_SectionDirectories[idx].PointerToRelocations,
									 m_SectionDirectories[idx].PointerToLinenumbers,
									 m_SectionDirectories[idx].NumberOfRelocations,
									 m_SectionDirectories[idx].NumberOfLinenumbers,
									 m_SectionDirectories[idx].Characteristics
									 );
	}

	std::wstring hexString = wbuf;
	return hexString;
}

//////////////////////////////////////////////////////////////////////////////////////////////
bool PEAnalyzer::GetHasImport() const
{
	return m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0
		&& m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0;
}

std::wstring PEAnalyzer::GetImportName() const
{
	std::wstring hexString = L"Import";
	return hexString;
}

std::wstring PEAnalyzer::GetImportRD() const
{
	std::wstring import = Buf2WHexString( (const char*)&m_Import[0], m_Import.size()*sizeof(IMAGE_IMPORT_DESCRIPTOR));
	std::wstring hexString = L"import: \r\n" + import+ L"\r\n";
	for (int idx=0; idx<m_ImportINT.size()-1; ++idx)
	{
		std::wstring importINT = Buf2WHexString( (const char*)&m_ImportINT[idx][0], m_ImportINT[idx].size()*sizeof(IMAGE_THUNK_DATA));
		wchar_t buf[32] = {0};
		swprintf(buf, L"importINT %d: \r\n", idx);
		hexString = hexString + buf + importINT + L"\r\n";
	}
	hexString = hexString + L"\r\n";

	for (int idx=0; idx<m_ImportIAT.size()-1; ++idx)
	{
		std::wstring importIAT = Buf2WHexString( (const char*)&m_ImportIAT[idx][0], m_ImportIAT[idx].size()*sizeof(IMAGE_THUNK_DATA));
		wchar_t buf[32] = {0};
		swprintf(buf, L"importIAT %d: \r\n", idx);
		hexString = hexString + buf + importIAT + L"\r\n";
	}
	return hexString;
}

void PEAnalyzer::readNullEndStringByVirtualAddr(DWORD virtualAddr, char* buf, DWORD bufBytes) const
{
	DWORD offsetSize = virtualAddr2RawPointer(virtualAddr, 4);
	if (offsetSize == 0xffffffff)
	{
		return;
	}
	int readSize = 0;
	while (true)
	{
		fseek(m_File, offsetSize+readSize, SEEK_SET);
		fread(buf+readSize, 1, 1, m_File);
		if (buf[readSize] == 0)
		{
			break;
		}
		else
		{
			readSize++;
		}
	}
}

std::wstring PEAnalyzer::readWStringByVirtualAddr(DWORD virtualAddr) const
{
	char nameBuf[256] = {0};
	readNullEndStringByVirtualAddr(virtualAddr, nameBuf, sizeof(nameBuf));
	wchar_t wName[256] = {0};
	ToUnicode(wName, nameBuf, sizeof(wName));
	return wName;
}

std::wstring PEAnalyzer::GetImportAD() const
{
	std::wstring hexString = L"";
	DWORD totalNum = 0;
	for (int dllIdx=0; dllIdx<m_Import.size()-1; ++dllIdx)
	{
		DWORD dllNameAddr = m_Import[dllIdx].Name;
		std::wstring dllName = readWStringByVirtualAddr(dllNameAddr);
		wchar_t importBuf[1024] = {0};
		swprintf(importBuf, L"%s(%u, %u, %u, %u, %u)", 
			dllName.c_str(),
			m_Import[dllIdx].OriginalFirstThunk,
			m_Import[dllIdx].TimeDateStamp,
			m_Import[dllIdx].ForwarderChain,
			m_Import[dllIdx].Name,
			m_Import[dllIdx].FirstThunk
			);
		hexString = hexString + importBuf + L"\r\n";
		totalNum += (m_ImportINT[dllIdx].size()-1);

		for (int funcIdx=0; funcIdx<m_ImportINT[dllIdx].size()-1; ++funcIdx)
		{
			DWORD addr = m_ImportINT[dllIdx][funcIdx].u1.Function;
			DWORD offset = virtualAddr2RawPointer(addr, 2);
			WORD Hint = 0;
			if (offset != 0xffffffff)
			{
				fseek(m_File, offset, SEEK_SET);
				fread(&Hint, 2, 1, m_File);
			}
			std::wstring intFuncName = readWStringByVirtualAddr(addr +2);
			wchar_t wbuf[1024] = {0};
			swprintf(wbuf, L"%d,%u,%u,%s", funcIdx, addr, 
				Hint, intFuncName.c_str());
			hexString = hexString + wbuf;

			memset(wbuf, 0, sizeof(wbuf));
			addr = m_ImportIAT[dllIdx][funcIdx].u1.Function;
			offset = virtualAddr2RawPointer(addr, 2);
			Hint = 0;
			if (offset != 0xffffffff)
			{
				fseek(m_File, offset, SEEK_SET);
				fread(&Hint, 2, 1, m_File);
			}
			intFuncName = readWStringByVirtualAddr(addr+2);
			swprintf(wbuf, L"==>%u,%u,%s\r\n",  addr, 
				Hint, intFuncName.c_str());
			hexString = hexString + wbuf;
		}
		hexString = hexString + L"\r\n";
	}
	wchar_t wbuf[1024] = {0};
	swprintf(wbuf, L"%d\r\n", totalNum);
	hexString = hexString + wbuf;

	return hexString;
}

///////////////////////////////////////////////////////////////////////////////////////////////
bool PEAnalyzer::GetHasIAT() const
{
	return m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size != 0
		&& m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress != 0;
}

std::wstring PEAnalyzer::GetIATName() const
{
	std::wstring hexString = L"Import Address Table";
	return hexString;
}

std::wstring PEAnalyzer::GetIATRD() const
{
	return Buf2WHexString((const char*)&m_IAT[0], m_IAT.size()*sizeof(IMAGE_THUNK_DATA));
}

std::wstring PEAnalyzer::GetIATAD() const
{
	std::wstring hexString = L"";
	DWORD totalNum = 0;
	for (int idx=0; idx<m_IAT.size(); ++idx)
	{
		DWORD addr = m_IAT[idx].u1.Function;
		if (addr == 0)
		{
			hexString = hexString + L"\r\n";
		}
		else
		{
			totalNum++;
			DWORD offset = virtualAddr2RawPointer(addr, 2);
			WORD Hint = 0;
			if (offset != 0xffffffff)
			{
				fseek(m_File, offset, SEEK_SET);
				fread(&Hint, 2, 1, m_File);
			}
			std::wstring intFuncName = readWStringByVirtualAddr(addr +2);
			wchar_t wbuf[1024] = {0};
			swprintf(wbuf, L"%d,%u,%u,%s\r\n", idx, addr, 
				Hint, intFuncName.c_str());
			hexString = hexString + wbuf;
		}
	}

	DWORD virtualAddr = m_OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	wchar_t wbuf[1024] = {0};
	swprintf(wbuf, L"%d\r\n", virtualAddr);
	hexString = wbuf + hexString;

	memset(wbuf, 0, sizeof(wbuf));
	swprintf(wbuf, L"%d\r\n", totalNum);
	hexString = hexString + wbuf;

	return hexString;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
