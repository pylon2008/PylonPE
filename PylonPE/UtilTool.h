#ifndef    _PE_UTIL_TOOL_H_
#define    _PE_UTIL_TOOL_H_

#include <string>

void ToHexString(char* dest, int destBytes, const char* src, int srcBytes);

// Multibyte������ַ���srcתΪUnicode��dest�������������ת�����Ŀ��ַ���
int ToUnicode(wchar_t* dest, const char* src, int destCount);

// Unicode������ַ���תΪMultibyte���������������ת�������ַ���
int ToMultibyte(char* dest, const wchar_t* src, int destCount);

unsigned char HexStrToUChar(const char* pHexStr);

std::wstring Buf2WHexString(const char* buf, int bufBytes);

#endif