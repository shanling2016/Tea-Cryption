// TeaCryption.cpp: 定义 DLL 应用程序的导出函数。
//
#include "Tea.h"
#include "XTea.h"
#include <windows.h>
#include <memory>

#ifdef TEACRYPTION_EXPORTS
#define TEA_API extern "C" __declspec(dllexport)
#else
#define TEA_API extern "C" __declspec(dllimport)
#endif

uint32_t *getKey(std::vector<char> key)
{
	uint32_t *res = (uint32_t *)malloc(4 * sizeof(uint32_t));
	memset(res, 0, 4 * sizeof(uint32_t));
	if (key.size() != 16) {
		return nullptr;
	}
	for (int i = 0; i < 4; i++) {
		uint32_t a = key[i * 4];
		a = (a << 8) | (unsigned char)key[(i * 4) + 1];
		a = (a << 8) | (unsigned char)key[(i * 4) + 2];
		a = (a << 8) | (unsigned char)key[(i * 4) + 3];
		*(res + i) = a;
	}
	return res;
}

/* 16轮 Tea 加密;公开外部调用接口 */
TEA_API BOOL WINAPI TeaEncrypt(
	LPCSTR lpszBuffer,
	DWORD nBufferSize,
	LPCSTR lpszkey,
	DWORD nKeySize,
	PVOID pOutBuf,
	PDWORD pOutBufLen)
{
	std::vector<char> vData;
	vData.resize(nBufferSize);
	memcpy_s(&vData[0], vData.size(), lpszBuffer, nBufferSize);

	std::vector<char> vKey;
	vKey.resize(nKeySize);
	memcpy_s(&vKey[0], vKey.size(), lpszkey, nKeySize);

	uint32_t *key_s = getKey(vKey);

	Tea tea;
	tea.NewCipher(key_s, std::move(vData));
	tea.Encrypt();

	free(key_s);

	std::vector<char> vResult;
	vResult = std::move(tea.tc.obuf);

	*pOutBufLen = vResult.size();

	if (pOutBuf == NULL)
		return FALSE;

	memcpy_s(pOutBuf, *pOutBufLen, &vResult[0], vResult.size());

	return TRUE;
}

/* 16轮 Tea 解密;公开外部调用接口 */
TEA_API BOOL WINAPI TeaDecrypt(
	LPCSTR lpszBuffer,
	DWORD nBufferSize,
	LPCSTR lpszkey,
	DWORD nKeySize,
	PVOID pOutBuf,
	PDWORD pOutBufLen)
{
	std::vector<char> vData;
	vData.resize(nBufferSize);
	memcpy_s(&vData[0], vData.size(), lpszBuffer, nBufferSize);

	std::vector<char> vKey;
	vKey.resize(nKeySize);
	memcpy_s(&vKey[0], vKey.size(), lpszkey, nKeySize);

	uint32_t *key_s = getKey(vKey);

	Tea tea;
	tea.NewCipher(key_s, std::move(vData));

	if (tea.Decrypt() != 0)
	{
		free(key_s);
		return FALSE;
	}

	for (int i = 0; i < 7; i++) {
		tea.tc.obuf.pop_back();
	}

	std::vector<char> vResult;
	vResult = std::move(tea.tc.obuf);

	*pOutBufLen = vResult.size();

	if (pOutBuf == NULL)
		return FALSE;

	memcpy_s(pOutBuf, *pOutBufLen, &vResult[0], vResult.size());

	return TRUE;
}

/* 32轮 Tea 加密;公开外部调用接口 */
TEA_API BOOL WINAPI XTeaEncrypt(
	LPCSTR lpszBuffer,
	DWORD nBufferSize,
	LPCSTR lpszkey,
	DWORD nKeySize,
	PVOID pOutBuf,
	PDWORD pOutBufLen)
{
	std::vector<char> vData;
	vData.resize(nBufferSize);
	memcpy_s(&vData[0], vData.size(), lpszBuffer, nBufferSize);

	std::vector<char> vKey;
	vKey.resize(nKeySize);
	memcpy_s(&vKey[0], vKey.size(), lpszkey, nKeySize);

	uint32_t *key_s = getKey(vKey);

	XTea tea;
	tea.NewCipher(key_s, std::move(vData));
	tea.Encrypt();

	free(key_s);

	std::vector<char> vResult;
	vResult = std::move(tea.tc.obuf);

	*pOutBufLen = vResult.size();

	if (pOutBuf == NULL)
		return FALSE;

	memcpy_s(pOutBuf, *pOutBufLen, &vResult[0], vResult.size());

	return TRUE;
}

/* 32轮 Tea 解密;公开外部调用接口 */
TEA_API BOOL WINAPI XTeaDecrypt(
	LPCSTR lpszBuffer,
	DWORD nBufferSize,
	LPCSTR lpszkey,
	DWORD nKeySize,
	PVOID pOutBuf,
	PDWORD pOutBufLen)
{
	std::vector<char> vData;
	vData.resize(nBufferSize);
	memcpy_s(&vData[0], vData.size(), lpszBuffer, nBufferSize);

	std::vector<char> vKey;
	vKey.resize(nKeySize);
	memcpy_s(&vKey[0], vKey.size(), lpszkey, nKeySize);

	uint32_t *key_s = getKey(vKey);

	XTea tea;
	tea.NewCipher(key_s, std::move(vData));

	if (tea.Decrypt() != 0)
	{
		free(key_s);
		return FALSE;
	}

	for (int i = 0; i < 7; i++) {
		tea.tc.obuf.pop_back();
	}

	std::vector<char> vResult;
	vResult = std::move(tea.tc.obuf);

	*pOutBufLen = vResult.size();

	if (pOutBuf == NULL)
		return FALSE;

	memcpy_s(pOutBuf, *pOutBufLen, &vResult[0], vResult.size());

	return TRUE;
}