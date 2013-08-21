#ifndef    _PE_UTIL_TOOL_H_
#define    _PE_UTIL_TOOL_H_

#include <string>

void ToHexString(char* dest, int destBytes, const char* src, int srcBytes);

// Multibyte编码的字符串src转为Unicode串dest，不处理错。返回转换出的宽字符数
int ToUnicode(wchar_t* dest, const char* src, int destCount);

// Unicode编码的字符串转为Multibyte串，不处理错。返回转换出的字符数
int ToMultibyte(char* dest, const wchar_t* src, int destCount);

unsigned char HexStrToUChar(const char* pHexStr);

std::wstring Buf2WHexString(const char* buf, int bufBytes);

#endif