#include "UtilTool.h"
#include <Windows.h>
#include <stdlib.h>
#include <vector>

int ToUnicode(wchar_t* dest, const char* src, int destCount)
{
	return MultiByteToWideChar(CP_ACP, NULL,
		src, -1,
		dest,
		destCount);
}

int ToMultibyte(char* dest, const wchar_t* src, int destCount)
{
	return WideCharToMultiByte(CP_ACP, NULL,
		src, -1,
		dest,
		destCount,NULL,NULL);
}

void ToHexString(char* dest, int destBytes, const char* src, int srcBytes)
{
	int element = 16;
	int time = srcBytes / element;
	int lastBytes = element;
	if (time*element != srcBytes)
	{
		lastBytes = srcBytes - time*element;
		time++;
	}

	for (int timeIdx=0; timeIdx<time; ++timeIdx)
	{
		int bytes = element;
		if (timeIdx == time-1)
		{
			bytes = lastBytes;
		}

		for (int idx=0; idx<bytes; ++idx)
		{
			int realSrcIdx = timeIdx * element + idx;
			int realDestIdx = timeIdx * (element*3 + 2) + idx*3;
			unsigned char value = src[realSrcIdx];
			_itoa_s(value, &dest[realDestIdx], 3, 16);
			if (dest[realDestIdx+1] == 0)
			{
				dest[realDestIdx+1] = dest[realDestIdx+0];
				dest[realDestIdx+0] = '0';
			}
			dest[realDestIdx+2] = ' ';
		}
		dest[timeIdx * (element*3 + 2)+element*3+0] = '\r';
		dest[timeIdx * (element*3 + 2)+element*3+1] = '\n';
	}

	for (int idx=0; idx<destBytes; ++idx)
	{
		if (dest[idx] == 0)
		{
			break;
		}

		if (dest[idx]>='a' && dest[idx]<='z')
		{
			dest[idx] = dest[idx] + ('A' - 'a');
		}
	}

	/*for (int idx=0; idx<srcBytes; ++idx)
	{
		unsigned char value = src[idx];
		_itoa_s(value, &dest[idx*3], 3, 16);
		if (dest[idx*3+1] == 0)
		{
			dest[idx*3+1] = dest[idx*3+0];
			dest[idx*3+0] = '0';
		}
		dest[idx*3+2] = ' ';
	}*/
}

unsigned char HexStrToUChar(const char* pHexStr)
{
	unsigned char transformed = 0;
	unsigned char highPart = *pHexStr;
	unsigned char lowPart = *(pHexStr + 1);

	if (highPart >= '0' && highPart <= '9')
	{
		highPart -= '0';
	}
	else if (highPart >= 'A' && highPart<= 'F')
	{
		highPart = highPart - 'A' + 10;
	}
	else if (highPart >= 'a' && highPart<= 'f')
	{
		highPart = highPart - 'a' + 10;
	}
	else
	{
		// throw
	}

	if (lowPart >= '0' && lowPart <= '9')
	{
		lowPart -= '0';
	}
	else if (lowPart >= 'A' && lowPart<= 'F')
	{
		lowPart = lowPart - 'A' + 10;
	}
	else if (lowPart >= 'a' && lowPart<= 'f')
	{
		lowPart = lowPart - 'a' + 10;
	}
	else
	{
		// throw
	}

	transformed = (highPart<<4) | lowPart;

	return transformed;
}

std::wstring Buf2WHexString(const char* inbuf, int bufBytes)
{
	std::vector<unsigned char> buf;
	buf.resize(bufBytes*4);
	memset(&buf[0], 0, buf.size());
	ToHexString((char*)&buf[0], buf.size(), inbuf, bufBytes);

	std::vector<wchar_t> wbuf;
	wbuf.resize( strlen((char*)&buf[0])*2+2 );
	memset(&wbuf[0], 0, wbuf.size()*sizeof(wchar_t));
	ToUnicode(&wbuf[0], (const char*)&buf[0], wbuf.size());
	std::wstring hexString = &wbuf[0];
	return hexString;
}