
#include <windows.h>
#include <memory>

#ifdef TEACRYPTION_EXPORTS
#define TEA_API extern "C" __declspec(dllexport)
#else
#define TEA_API extern "C" __declspec(dllimport)
#endif

extern BOOL WINAPI TeaEncrypt(
	LPCSTR lpszBuffer,
	DWORD nBufferSize,
	LPCSTR lpszkey,
	DWORD nKeySize,
	PVOID pOutBuf,
	PDWORD pOutBufLen);

extern BOOL WINAPI TeaDecrypt(
	LPCSTR lpszBuffer,
	DWORD nBufferSize,
	LPCSTR lpszkey,
	DWORD nKeySize,
	PVOID pOutBuf,
	PDWORD pOutBufLen);

extern BOOL WINAPI XTeaEncrypt(
	LPCSTR lpszBuffer,
	DWORD nBufferSize,
	LPCSTR lpszkey,
	DWORD nKeySize,
	PVOID pOutBuf,
	PDWORD pOutBufLen);

extern BOOL WINAPI XTeaDecrypt(
	LPCSTR lpszBuffer,
	DWORD nBufferSize,
	LPCSTR lpszkey,
	DWORD nKeySize,
	PVOID pOutBuf,
	PDWORD pOutBufLen)