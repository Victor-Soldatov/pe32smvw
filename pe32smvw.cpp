#define STRSAFE_LIB

/**********************************************************************************************************************************************************************/
//	pe32smvw - PE32 data directories to sections map viewer console utility ver. 1.0.0.1
//	Options:
//		-V(erbose)									-		verbose output
//		-A(dd):[SectionName=]Value(p)				-		add 'virtual' section with [SectionName] as name (tag) and Value bytes size (if p is present - Value is in pages)
//		-F(ile add):[SectionName=]Filename[.ext]	-		add real (initialized) data section with [SectionName] as name (tag) and Filename as content
//		
/*********************************************************************************************************************************************************************/

//"d:\VCPP\2017\TestPE32\Debug\TestPE32.EXE" -v -f:.xdata0=content.dat
//"d:\VCPP\2017\TestPE32\Debug\TestPE32.EXE" -v -a:.XData0=16p

#include <Windows.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <Aclapi.h>
#include <ImageHlp.h>
#include <Psapi.h>
#include <Wincrypt.h>
#include <Softpub.h>
#include <mscat.h>

#pragma comment(lib, "Version.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Imagehlp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Crypt32.lib")

#include "resource.h"
#include "MsgTbl.h"
#pragma hdrstop

#ifndef MAX_KEY_LENGTH
#define MAX_KEY_LENGTH								255
#endif

#ifndef MAX_VALUE_NAME
#define MAX_VALUE_NAME								16383
#endif

/*
https://docs.microsoft.com/ru-ru/windows/desktop/api/winnt/ns-winnt-image_file_header
... Windows loader limits the number of sections to 96 ...
*/

#define SECTIONS_TOTAL_MAX							96
#define DISPOSE_BUF(p)								DisposeBuffer(reinterpret_cast<void**>((p)));
#define CONSOLE_PROCESS_LIST_LAMBDA					16UL

// Errors codes' definitions
#define ERROR_TOO_FEW_ARGS							-1
#define ERROR_INVALID_OPTION_KEY					-2
#define ERROR_FILE_IS_NOT_FOUND						-3
#define ERROR_FILE_ACCESS_FAILED					-4
#define ERROR_UNABLE_MAP_FILE						-5
#define ERROR_MAP_VIEW_CREATE_FAILED				-6
#define ERROR_DOS_STUB_IS_INVALID					-7
#define ERROR_PE_HEADERS_ARE_INVALID				-8
#define ERROR_NOT_32_BIT_IMAGE						-9
#define ERROR_SECTION_ALREADY_EXISTS				-10
#define ERROR_TOO_MUCH_SECTIONS						-11
#define ERROR_NOT_ENOUGH_SPACE						-12
#define ERROR_CHECKSUM_RECALCULATING_FAILED			-13

const __wchar_t lpwszEventMessageFile[] = L"EventMessageFile";
const __wchar_t lpwszTypesSupported[] = L"TypesSupported";
const __wchar_t lpwszCategoryMessageFile[] = L"CategoryMessageFile";
const __wchar_t lpwszCategoryCount[] = L"CategoryCount";
const __wchar_t lpwszEventLoggerRootKey[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application";

const __wchar_t lpwszProductIdent[] = L"\\StringFileInfo\\040004b0\\ProductIdent";
const __wchar_t lpwszFileDescription[] = L"\\StringFileInfo\\040004b0\\FileDescription";
const __wchar_t lpwszFileVersion[] = L"\\StringFileInfo\\040004b0\\FileVersion";
const __wchar_t lpwszLegalCopyright[] = L"\\StringFileInfo\\040004b0\\LegalCopyright";

const char lpwszSectNamePattern[] = "._data";

bool g_fbDigSig(false);
bool g_fbDigSigIsValid(false);
int g_nInvalidOptNo(-1);
int g_nInvalidCharIndex(-1);
bool g_fbVerbose(false);
bool g_fbAdd(false);
bool g_fbFileAdd(false);
bool g_fbOverflow(false);
size_t g_nSectionSize(0);
bool g_fbPageUnits(false);
bool g_fbOptionsAreCorrect(true);
bool g_fbSectionNamePassed(false);
bool g_fbFileSectionNamePassed(false);
bool g_fbDataFileNamePassed(false);
WORD g_wNumberOfSections(0);

__wchar_t g_wszSectionName[MAX_PATH] = { 0 };
__wchar_t g_wszFileSectionName[MAX_PATH] = { 0 };
__wchar_t g_wszFileName[MAX_PATH] = { 0 };

char g_acNativeSectionName[IMAGE_SIZEOF_SHORT_NAME] = { 0 };
__wchar_t g_awcNativeSectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
char g_acNativeFileSectionName[IMAGE_SIZEOF_SHORT_NAME] = { 0 };
__wchar_t g_awcFileNativeSectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };

__wchar_t g_wszIdent[MAX_PATH] = { 0 };

void DisposeBuffer(__inout __notnull void** lppArray)
{
	HANDLE hDefHeap(::GetProcessHeap());
	if (hDefHeap && lppArray && *lppArray)
	{
		if (::HeapFree(hDefHeap, 0, *lppArray))
			*lppArray = nullptr;
	}
}

bool AllocBufferEx(__in DWORD dwNewArrayLen, __in DWORD dwItemSize, __inout __notnull void** lppArray)
{
	bool fbDone(false);
	HANDLE hDefHeap(::GetProcessHeap());
	if (hDefHeap && lppArray)
	{
		if (*lppArray)
			DisposeBuffer(lppArray);

		if (!(*lppArray) && dwNewArrayLen && dwItemSize)
		{
			*lppArray = ::HeapAlloc(hDefHeap, HEAP_ZERO_MEMORY, dwNewArrayLen * dwItemSize);
			if (*lppArray)
				fbDone = true;
		}
	}
	return fbDone;
}

__inline bool AllocBuffer(__in DWORD dwNewArrayLen, __inout __notnull LPDWORD* lpdwArray)
{
	return AllocBufferEx(dwNewArrayLen, sizeof(DWORD), reinterpret_cast<void**>(lpdwArray));
}

BOOL GetFileSD(__in __nullterminated __wchar_t* const lpwszFileName, __out_opt PSECURITY_DESCRIPTOR *pFileSD, __out_opt PACL *pACL)
{
	BOOL bRetVal(FALSE);
	SECURITY_INFORMATION secInfo(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);

	if (lpwszFileName)
	{
		HANDLE hFile(::CreateFile(lpwszFileName, READ_CONTROL, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
		if (INVALID_HANDLE_VALUE != hFile)
		{
			bRetVal = (ERROR_SUCCESS == ::GetSecurityInfo(hFile, SE_FILE_OBJECT, secInfo, nullptr, nullptr, pACL, nullptr, pFileSD));
			::CloseHandle(hFile);
		}
	}
	return bRetVal;
}

BOOL CanAccessFile(__in __nullterminated __wchar_t* const lpwszFileName, __in DWORD genericAccessRights)
{
	BOOL bRet(FALSE);
	if (lpwszFileName)
	{
		PACL pFileDACL(nullptr);
		PSECURITY_DESCRIPTOR pFileSD(nullptr);
		if (GetFileSD(lpwszFileName, &pFileSD, &pFileDACL))
		{
			if (!pFileDACL)
				bRet = TRUE;
			else
			{
				HANDLE hToken(nullptr);
				if (::OpenProcessToken( ::GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &hToken ))
				{
					HANDLE hImpersonatedToken(nullptr);
					if (::DuplicateToken( hToken, SecurityImpersonation, &hImpersonatedToken ))
					{
						GENERIC_MAPPING mapping = { 0xFFFFFFFF };
						PRIVILEGE_SET privileges = { 0 };
						DWORD grantedAccess = 0, privilegesLength = sizeof( privileges );

						mapping.GenericRead = FILE_GENERIC_READ;
						mapping.GenericWrite = FILE_GENERIC_WRITE;
						mapping.GenericExecute = FILE_GENERIC_EXECUTE;
						mapping.GenericAll = FILE_ALL_ACCESS;

						::MapGenericMask(&genericAccessRights, &mapping);

						if (!::AccessCheck(pFileSD, hImpersonatedToken, genericAccessRights, &mapping, &privileges, &privilegesLength, &grantedAccess, &bRet))
							bRet = FALSE;

						::CloseHandle(hImpersonatedToken);
					}
					::CloseHandle(hToken);
				}
				if (pFileSD)
					::LocalFree(pFileSD);
			}
		}
	}
	return bRet;
}

__inline __wchar_t MapChar(__in char aChar)
{
	char aChars[2] = { aChar, 0 };
	__wchar_t wChars[2] = { 0 };
	if (0 == ::MultiByteToWideChar(1252, MB_PRECOMPOSED, aChars, -1, wChars, 2))
		wChars[0] = L'?';
	return (wChars[0]);
}

__inline char MapWChar(__in __wchar_t aWChar)
{
	__wchar_t wChars[2] = { aWChar, 0 };
	char aTChars[2] = { 0 };
	BOOL fbDefChar(FALSE);
	if (0 == ::WideCharToMultiByte (1252, WC_NO_BEST_FIT_CHARS, &wChars[0], -1, aTChars, 2, nullptr, &fbDefChar) || fbDefChar)
		aTChars[0] = '?';
	return (aTChars[0]);
}

bool LoadErrorMessageW(__in LANGID LangID, __in DWORD dwOSErrorCode, __out __wchar_t* lpwszErrorMsgBuf, __in size_t ncBufLen)
{
	bool fbDone(false);
	if (lpwszErrorMsgBuf && ncBufLen)
	{
		LPVOID lpMsgBuf(nullptr);	

		if ((dwOSErrorCode >= 12000) && (dwOSErrorCode <= 12174))
			::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
			::GetModuleHandleW(L"WININET.DLL"), dwOSErrorCode, LangID, reinterpret_cast<LPWSTR>(&lpMsgBuf), 0, nullptr);
		else
			::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr, dwOSErrorCode, LangID, reinterpret_cast<LPWSTR>(&lpMsgBuf), 0, nullptr);

		if (lpMsgBuf)
		{
			 fbDone = SUCCEEDED(::StringCchCopyW(lpwszErrorMsgBuf, ncBufLen, reinterpret_cast<__wchar_t*>(lpMsgBuf)));
			::LocalFree(lpMsgBuf);
		}
	}

	return (fbDone);
}

bool IsUserAdmin(void)
{
	bool fbAdmin(false);
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup; 
	BOOL b(::AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)); 
	if(b) 
	{
		if (::CheckTokenMembership(nullptr, AdministratorsGroup, &b))
			fbAdmin = true;
		::FreeSid(AdministratorsGroup); 
	}
	return(fbAdmin);
}

TOKEN_ELEVATION_TYPE GetElevationType(void) 
{
    HANDLE hToken(nullptr); 
    TOKEN_ELEVATION_TYPE type((TOKEN_ELEVATION_TYPE) 0);
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
        TOKEN_ELEVATION_TYPE ElevationType;
        DWORD cbSize = sizeof(TOKEN_ELEVATION_TYPE);
        if (::GetTokenInformation(hToken, TokenElevationType, &ElevationType, sizeof(ElevationType), &cbSize))
			type = ElevationType;
    }

    if (hToken) 
		::CloseHandle(hToken);

    return type;
}

size_t StrLen(__in __nullterminated __wchar_t* const lpwszStr)
{
	size_t cnStrLen(0);
	if (lpwszStr)
		if (FAILED(::StringCchLengthW(lpwszStr, STRSAFE_MAX_CCH, &cnStrLen)))
			cnStrLen = 0;
	return (cnStrLen);
}

size_t StrSize(__in __nullterminated __wchar_t* const lpwszString)
{
	size_t cnSize(0);
	if (lpwszString)
		if FAILED(::StringCbLengthW(lpwszString, STRSAFE_MAX_CCH, &cnSize))
			cnSize = 0;
	return (cnSize);
}

__checkReturn __nullterminated __wchar_t* LoadStringEx(__in __notnull HINSTANCE hInstance, __in DWORD MessageID, __in WORD LangID)
{
	wchar_t* lpStr(nullptr);
	HRSRC hResource(::FindResourceExW(hInstance, RT_STRING, MAKEINTRESOURCEW(MessageID / 16 + 1), LangID));
	HANDLE hProcessHeap(::GetProcessHeap());
	if (hResource && hProcessHeap) 
	{
		HGLOBAL hGlobal(::LoadResource(hInstance, hResource));
		if (hGlobal) 
		{
			const __wchar_t* pwszRes(reinterpret_cast<const __wchar_t*>(::LockResource(hGlobal)));
			if (pwszRes) 
			{
				for (DWORD i = 0; i < (MessageID & 15); i++) 
					pwszRes += 1 + *(WORD*)(pwszRes);


				__wchar_t* pwszStr(reinterpret_cast<__wchar_t*>(::HeapAlloc(hProcessHeap, HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, (*reinterpret_cast<WORD*>(const_cast<__wchar_t*>(pwszRes)) + 1) * sizeof(__wchar_t))));

				if (pwszStr != nullptr) 
				{
					pwszStr[*(WORD*)(pwszRes)] = L'\0';
					::CopyMemory(pwszStr, pwszRes + 1, *reinterpret_cast<WORD*>(const_cast<__wchar_t*>(pwszRes)) * sizeof(__wchar_t));
				}
				lpStr = pwszStr;
				UnlockResource(pwszRes);
			}
			::FreeResource(hGlobal);
		}
	} 
	return lpStr;
}

void ReleaseLoadedString(__in __notnull __wchar_t* const lpwszString)
{
	HANDLE hProcessHeap(::GetProcessHeap());
	if (lpwszString && hProcessHeap) 
		::HeapFree(hProcessHeap, 0, const_cast<__wchar_t*>(lpwszString));
}

void ShowString(__in __notnull HANDLE hStdOut, __in __nullterminated __wchar_t* const lpwszString)
{
	DWORD dwWritten(0);
	if (hStdOut && lpwszString)
		::WriteConsoleW(hStdOut, lpwszString, StrLen(lpwszString), &dwWritten, nullptr);
}

void ShowStringEx(__in __notnull HANDLE hStdOut, __in __nullterminated __wchar_t* const lpwszString, __in WORD wForeAttr, __in WORD wBackAttr)
{
	DWORD dwWritten(0);
	if (hStdOut && lpwszString)
	{
		CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
		if (::GetConsoleScreenBufferInfo(hStdOut, &csbi) && ::SetConsoleTextAttribute(hStdOut, wForeAttr | wBackAttr))
		{
			::WriteConsoleW(hStdOut, lpwszString, StrLen(lpwszString), &dwWritten, nullptr);
			::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
		}
	}
}

void ShowChar(__in __notnull HANDLE hStdOut, __in char aChar)
{
	DWORD dwWritten(0);
	if (hStdOut && aChar)
		::WriteConsoleA(hStdOut, &aChar, 1, &dwWritten, nullptr);
}

void ShowResourceString(__in __notnull HANDLE hStdOut, __in DWORD dwStringID, __in LANGID LangID)
{
	HMODULE hModule(::GetModuleHandleW(nullptr));

	if (hStdOut && hModule)
	{
		__wchar_t* lpwszResString(LoadStringEx(hModule, dwStringID, LangID));
		if (lpwszResString)
		{
			ShowString(hStdOut, lpwszResString);
			ReleaseLoadedString(lpwszResString);
		}
	}
}

void ShowResourceStringEx(__in __notnull HANDLE hStdOut, __in DWORD dwStringID, __in LANGID LangID, __in WORD wForeAttr, __in WORD wBackAttr)
{
	HMODULE hModule(::GetModuleHandleW(nullptr));

	if (hStdOut && hModule)
	{
		__wchar_t* lpwszResString(LoadStringEx(hModule, dwStringID, LangID));
		if (lpwszResString)
		{
			ShowStringEx(hStdOut, lpwszResString, wForeAttr, wBackAttr);
			ReleaseLoadedString(lpwszResString);
		}
	}
}

void ShowResourceStringArgs(__in __notnull HANDLE hStdOut, __in DWORD dwStringID, __in LANGID LangID, ...)
{
	va_list argptr;
	va_start(argptr, LangID);

	HMODULE hModule(::GetModuleHandleW(nullptr));

	if (hStdOut && hModule)
	{
		__wchar_t* lpwszResString(LoadStringEx(hModule, dwStringID, LangID));
		if (lpwszResString)
		{
			__wchar_t szOutStr[2 * MAX_PATH] = { 0 };
			if (SUCCEEDED(::StringCchVPrintfW(szOutStr, 2 * MAX_PATH, lpwszResString, argptr)))
				ShowString(hStdOut, szOutStr);
			ReleaseLoadedString(lpwszResString);
		}
	}
	va_end(argptr);
}

void ShowResourceStringArgsEx(__in __notnull HANDLE hStdOut, __in DWORD dwStringID, __in LANGID LangID, __in WORD wForeAttr, __in WORD wBackAttr, ...)
{
	va_list argptr;
	va_start(argptr, wBackAttr);

	HMODULE hModule(::GetModuleHandleW(nullptr));

	if (hStdOut && hModule)
	{
		__wchar_t* lpwszResString(LoadStringEx(hModule, dwStringID, LangID));
		if (lpwszResString)
		{
			__wchar_t szOutStr[2 * MAX_PATH] = { 0 };
			if (SUCCEEDED(::StringCchVPrintfW(szOutStr, 2 * MAX_PATH, lpwszResString, argptr)))
				ShowStringEx(hStdOut, szOutStr, wForeAttr, wBackAttr);
			ReleaseLoadedString(lpwszResString);
		}
	}
	va_end(argptr);
}

void ShowSysErrorMsg(__in DWORD dwErrorCode, __in __notnull HANDLE hStdOut)
{
	if (hStdOut)
	{
		__wchar_t wszErrorMsgBuf[MAX_PATH] = { 0 };
		__wchar_t szNewLine[3] = { L'\r', L'\n', 0	};

		CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
		BOOL fbRestoreConAttr(FALSE);
		fbRestoreConAttr = ::GetConsoleScreenBufferInfo(hStdOut, &csbi) && ::SetConsoleTextAttribute(hStdOut, FOREGROUND_RED | FOREGROUND_INTENSITY);

		if (LoadErrorMessageW(MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dwErrorCode, &wszErrorMsgBuf[0], MAX_PATH))
			ShowString(hStdOut, &wszErrorMsgBuf[0]);
		else
			ShowResourceStringArgs(hStdOut, IDS_ERROR_SYSTEM, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), dwErrorCode);
		ShowString(hStdOut, szNewLine);

		if (fbRestoreConAttr)
			::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
	}
}

void ShowUsage(__in __notnull HANDLE hStdOut)
{
	if (hStdOut)
	{
		__wchar_t* lpwszUsageStr(LoadStringEx(::GetModuleHandleW(nullptr), IDS_USAGE_STRING, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)));
		if (lpwszUsageStr)
		{
			CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
			BOOL fbRestoreConAttr(FALSE);
			fbRestoreConAttr = ::GetConsoleScreenBufferInfo(hStdOut, &csbi) && ::SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);

			ShowString(hStdOut, lpwszUsageStr);
			ReleaseLoadedString(lpwszUsageStr);

			if (fbRestoreConAttr)
				::SetConsoleTextAttribute(hStdOut, csbi.wAttributes);
		}
	}
}

bool TryStrToSizeW(__in __nullterminated __wchar_t* const wszString, __out size_t& nValue, __out bool& fbPages, __out bool& fbOverflow)
{
	bool fbCompleted(false);
	size_t nStrLen(0);
	ULARGE_INTEGER cnValue = { 0 };
	bool fbPagesUnits(false);
	if (wszString && 0 != (nStrLen = StrLen(wszString)))
	{
		__wchar_t wszDecimal[] = L"0123456789";
		if (1 < nStrLen)
		{
			//	Check last symbol
			if (nStrLen)
			{
				switch(wszString[nStrLen - 1])
				{
				case L'P':
				case L'p':
					//	Pages flag
					fbPagesUnits = true;
					nStrLen--;
					break;
				}

				if (nStrLen)
				{
					//	Unwrap size value
					bool fbInvalidSymbol(false);
					__wchar_t* wszPos(nullptr);
					for (size_t nIndex(0); nIndex < nStrLen; ++nIndex)
					{
						if (nullptr != (wszPos = ::StrChrW(&wszDecimal[0], wszString[nIndex])))
							cnValue.QuadPart = 10 * cnValue.QuadPart + (wszPos[0] - L'0');
						else
						{
							fbInvalidSymbol = true;
							break;
						}
					}

					if (!fbInvalidSymbol && (!cnValue.HighPart) && (cnValue.LowPart < MAXINT32))
					{
						nValue = cnValue.LowPart;
						fbPages = fbPagesUnits;
						fbOverflow = false;
						fbCompleted = true;
					}
					else
						fbOverflow = true;
				}
			}
		}
		else
		{
			//	nStrLen == 1
			__wchar_t* wszPos(nullptr);
			if (nullptr != (wszPos = ::StrChrW(&wszDecimal[0], wszString[0])))
			{
				nValue = wszPos[0] - L'0';
				fbPages = fbPagesUnits;
				fbOverflow = false;
				fbCompleted = true;
			}
		}
	}
	return (fbCompleted);
}

bool CheckOptArguments(__in int nArgsCount, __in __notnull __wchar_t** const argv)
{
	bool fbStatus(true);
	bool fbPreSymbol(false);		//	Symbols: /\-
	bool fbVerboseMode(false);
	bool fbAddMode(false);
	bool fbFileAddMode(false);
	__wchar_t awszSectionName[MAX_PATH] = { 0 };
	__wchar_t awszFileSectionName[MAX_PATH] = { 0 };
	__wchar_t awszFileName[MAX_PATH] = { 0 };
	__wchar_t awszSectionSize[MAX_PATH] = { 0 };
	int nSectionSizeIndex(0);
	int nFileNameIndex(0);
	size_t cnSectionSize(0);
	bool fbSectionNamePassed(false);
	bool fbFileSectionNamePassed(false);
	bool fbSizeInPages(false);
	bool fbSizeOverflow(false);
	int nInvOpt(-1);
	int nInvalidSymbol(-1);
	bool fbFilenameCopied(false);

	for (int i(0); i < nArgsCount; ++i)
	{
		size_t nArgLineLen(StrLen(argv[i]));
		if (nArgLineLen)
			for (size_t nCharIndex(0); nCharIndex < nArgLineLen; ++nCharIndex)
			{
				if (argv[i][nCharIndex] != L' ')
				{
					switch(argv[i][nCharIndex])
					{
					case L'/':
					case L'\\':
					case L'-':
						fbPreSymbol = true;
						continue;
					}
					if (fbPreSymbol)
					{
						switch(argv[i][nCharIndex])
						{
						case L'V':
						case L'v':
							//	Verbose mode
							fbPreSymbol = false;
							if (!fbVerboseMode)
								fbVerboseMode = true;
							else		//	Duplicated option. Return error.
							{
								fbStatus = false;
								nInvOpt = i;
								nInvalidSymbol = static_cast<int>(nCharIndex);
							}
							break;
						case L'f':
						case L'F':
							fbPreSymbol = false;
							if (!fbFileAddMode)
							{
								fbFileAddMode = true;
								//	Keep going parsing for file name to add ...
								bool fbAddDelimiterSymbol(false);
								for (nCharIndex++; nCharIndex < nArgLineLen; ++nCharIndex)
									if ((L' ' == argv[i][nCharIndex]) || (L':' == argv[i][nCharIndex]))
									{
										if (L' ' == argv[i][nCharIndex])
											continue;
										else
										{
											if (!fbAddDelimiterSymbol)
												fbAddDelimiterSymbol = true;
											else	//	Dulicated delimiter
											{
												fbStatus = false;
												nInvOpt = i;
												nInvalidSymbol = static_cast<int>(nCharIndex);
												break;
											}
										}
									}
									else
										break;
								//	Add mode option key may be:
								//	1. f:Filename
								//	2. f:SectionName=Filename
								//	Just copy symbols to buffers
								bool fbFilenameIsQuoted(false);
								if (fbStatus)
								{
									for (; nCharIndex < nArgLineLen; ++nCharIndex)
									{
										switch(argv[i][nCharIndex])
										{
										case L'/':
										case L'\\':
										case L'-':
											//	Filler is in buffer
											fbFilenameCopied = true;
											break;
										case L' ':
											if (fbFilenameIsQuoted)
											{
												awszFileName[nFileNameIndex++] = argv[i][nCharIndex];
												break;
											}
											else
												continue;
										case L'"':
											if (!fbFilenameIsQuoted)
												fbFilenameIsQuoted = true;
											else
												fbFilenameCopied = true;
										case L'=':
											//	Section name is passed
											if (!fbFilenameCopied)
											{
												fbFileSectionNamePassed = true;
												//	All awszFileName[] stuff is awszFileSectionName[], so move it.
												for (int nSSIndex(0); nSSIndex < nFileNameIndex; ++nSSIndex)
												{
													awszFileSectionName[nSSIndex] = awszFileName[nSSIndex];
													awszFileName[nSSIndex] = 0;
												}
												nFileNameIndex = 0;
											}
											else
											{
												fbStatus = false;
												nInvOpt = i;
												nInvalidSymbol = static_cast<int>(nCharIndex);
											}
											break;
										default:
											if (!fbFilenameCopied)
												awszFileName[nFileNameIndex++] = argv[i][nCharIndex];
											else
											{
												fbStatus = false;
												nInvOpt = i;
												nInvalidSymbol = static_cast<int>(nCharIndex);
											}
											break;
										}
										if (!fbStatus)
											break;
									}
									if (fbStatus)
										fbFilenameCopied = 0 != StrLen(awszFileName);
								}
							}
							else		//	Duplicated option. Return error.
							{
								fbStatus = false;
								nInvOpt = i;
								nInvalidSymbol = static_cast<int>(nCharIndex);
							}
							break;
						case L'a':
						case L'A':
							//	Add mode
							fbPreSymbol = false;
							if (!fbAddMode)
							{
								fbAddMode = true;
								//	Keep going parsing for section's size value ...
								bool fbAddDelimiterSymbol(false);
								for (nCharIndex++; nCharIndex < nArgLineLen; ++nCharIndex)
									if ((L' ' == argv[i][nCharIndex]) || (L':' == argv[i][nCharIndex]))
									{
										if (L' ' == argv[i][nCharIndex])
											continue;
										else
										{
											if (!fbAddDelimiterSymbol)
												fbAddDelimiterSymbol = true;
											else	//	Dulicated delimiter
											{
												fbStatus = false;
												nInvOpt = i;
												nInvalidSymbol = static_cast<int>(nCharIndex);
												break;
											}
										}
									}
									else
										break;
								//	Add mode option key may be:
								//	1. A:Value(p)
								//	2. A:SectionName=Value(p)
								//	Just copy symbols to buffers
								bool fbValueCopied(false);
								if (fbStatus)
								{
									for (; nCharIndex < nArgLineLen; ++nCharIndex)
										switch(argv[i][nCharIndex])
										{
										case L'/':
										case L'\\':
										case L'-':
											//	Filler is in buffer
											fbValueCopied = true;
											break;
										case L' ':
											continue;
										case L'=':
											//	Section name is passed
											if (!fbSectionNamePassed)
											{
												fbSectionNamePassed = true;
												//	All szSectionSize[] stuff is awSectionName[], so move it.
												for (int nSSIndex(0); nSSIndex < nSectionSizeIndex; ++nSSIndex)
												{
													awszSectionName[nSSIndex] = awszSectionSize[nSSIndex];
													awszSectionSize[nSSIndex] = 0;
												}
												nSectionSizeIndex = 0;
											}
											else
											{
												fbStatus = false;
												nInvOpt = i;
												nInvalidSymbol = static_cast<int>(nCharIndex);
											}
											break;
										default:
											awszSectionSize[nSectionSizeIndex++] = argv[i][nCharIndex];
											break;
										}

									if (!TryStrToSizeW(awszSectionSize, cnSectionSize, fbSizeInPages, fbSizeOverflow))
									{
										fbStatus = false;
										nInvOpt = i;
										nInvalidSymbol = static_cast<int>(nCharIndex);
									}
								}
							}
							else		//	Duplicated option. Return error.
							{
								fbStatus = false;
								nInvOpt = i;
								nInvalidSymbol = static_cast<int>(nCharIndex);
							}
							break;
						default:
							fbStatus = false;
							nInvOpt = i;
							nInvalidSymbol = static_cast<int>(nCharIndex);
							break;
						}
					}
					else
					{
						fbStatus = false;
						nInvOpt = i;
						nInvalidSymbol = static_cast<int>(nCharIndex);
					}
				}
				if (!fbStatus)
					break;
			}
		if (!fbStatus)
			break;
	}

	if (fbStatus)
	{
		g_fbVerbose = fbVerboseMode;
		g_fbAdd = fbAddMode;
		g_nSectionSize = cnSectionSize;
		g_fbPageUnits = fbSizeInPages;
		g_fbOverflow = fbSizeOverflow;
		//	Move Section name
		g_fbSectionNamePassed = fbSectionNamePassed;
		if (fbSectionNamePassed)
			for (size_t i(0); i < MAX_PATH; ++i)
			{
				if (!awszSectionName[i])
					break;
				g_wszSectionName[i] = awszSectionName[i];
			}

		g_fbFileAdd = fbFileAddMode;
		g_fbDataFileNamePassed = fbFilenameCopied;
		g_fbFileSectionNamePassed = fbFileSectionNamePassed;
		if (fbFileAddMode)
		{
			for (size_t i(0); i < MAX_PATH; ++i)
			{
				if (!awszFileSectionName[i])
					break;
				g_wszFileSectionName[i] = awszFileSectionName[i];
			}
			for (size_t i(0); i < MAX_PATH; ++i)
			{
				if (!awszFileName[i])
					break;
				g_wszFileName[i] = awszFileName[i];
			}
		}
	}
	else
	{
		g_nInvalidOptNo = nInvOpt;
		g_nInvalidCharIndex = nInvalidSymbol;
		g_fbOverflow = fbSizeOverflow;
	}
	return (fbStatus);	
}

bool CheckEventSrcRegistration(__in __nullterminated __wchar_t* const lpwszLogName,  __in __nullterminated __wchar_t* const lpwszMsgTableFile)
{
	HKEY hKey(nullptr), hk(nullptr); 
	DWORD dwData(0), dwDisp(0), dwCategoryNum(1);
	bool fbChecked(false);

	if (ERROR_SUCCESS == ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, lpwszEventLoggerRootKey, 0, KEY_WRITE, &hKey)) 
	{
		//	Looking for <lpwszLogName> under hKey
		__wchar_t achKey[MAX_KEY_LENGTH] = { 0 };
		__wchar_t achValue[MAX_PATH] = { 0 };
		DWORD    cbName(0);
		DWORD    cnSubKeys(0);

		bool fbKeyExists(false);

		if (ERROR_SUCCESS == ::RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &cnSubKeys, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) && cnSubKeys)
		{
			for (DWORD i(0); i < cnSubKeys; ++i) 
			{ 
				cbName = MAX_KEY_LENGTH;
				if (ERROR_SUCCESS == ::RegEnumKeyExW(hKey, i, achKey, &cbName, nullptr, nullptr, nullptr, nullptr))
				{
					if (CSTR_EQUAL == ::CompareStringW(LOCALE_NEUTRAL, NORM_IGNORECASE, achKey, cbName, lpwszLogName, -1))
					{
						fbKeyExists = true;
						break;
					}
				}
			}
		}

		LSTATUS Status;
		if (fbKeyExists)
			Status = ::RegOpenKeyExW(hKey, lpwszLogName, 0, KEY_WRITE, &hk);
		else
			Status = ::RegCreateKeyExW(hKey, lpwszLogName, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, &dwDisp);

		if (ERROR_SUCCESS == Status) 
		{ 
			// Get/set the name of the message file.  
			bool bEventMsgFile(false);
			DWORD dwValueType(0);
			DWORD dwValueLen(MAX_PATH);

			if (ERROR_FILE_NOT_FOUND != (Status = ::RegQueryValueExW(hk, lpwszEventMessageFile, nullptr, &dwValueType, reinterpret_cast<LPBYTE>(achValue), &dwValueLen)) && ERROR_SUCCESS == Status)
				bEventMsgFile = (CSTR_EQUAL == ::CompareStringW(LOCALE_NEUTRAL, NORM_IGNORECASE, achValue, dwValueLen, lpwszLogName, -1));
			if (!bEventMsgFile)
				Status = ::RegSetValueExW(hk, lpwszEventMessageFile, 0, REG_EXPAND_SZ, reinterpret_cast<LPBYTE>(const_cast<__wchar_t*>(lpwszMsgTableFile)), static_cast<DWORD>(StrSize(lpwszMsgTableFile) + sizeof(__wchar_t)));
			if (ERROR_SUCCESS == Status)
			{ 
				// Get/set the supported event types.  
				dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE; 
				DWORD dwValue(0);
				dwValueLen = sizeof(DWORD);
				bool bTypesSupported(false);

				if (ERROR_FILE_NOT_FOUND != (Status = ::RegQueryValueExW(hk, lpwszTypesSupported, nullptr, &dwValueType, reinterpret_cast<LPBYTE>(dwValue), &dwValueLen)) && ERROR_SUCCESS == Status)
					bTypesSupported = (dwData == dwValue);
				if (!bTypesSupported)
					Status = ::RegSetValueExW(hk, lpwszTypesSupported, 0, REG_DWORD, (LPBYTE) &dwData, sizeof(DWORD));
				if (ERROR_SUCCESS == Status)
				{ 
					// Get/set the category message file and number of categories.
					dwValueLen = MAX_PATH;
					ZeroMemory(achValue, sizeof(__wchar_t) * MAX_PATH);
					bool bCategoryMessageFile(false);

					if (ERROR_FILE_NOT_FOUND != (Status = ::RegQueryValueExW(hk, lpwszCategoryMessageFile, nullptr, &dwValueType, reinterpret_cast<LPBYTE>(achValue), &dwValueLen)) && ERROR_SUCCESS == Status)
						bCategoryMessageFile = (CSTR_EQUAL == ::CompareStringW(LOCALE_NEUTRAL, NORM_IGNORECASE, achValue, dwValueLen, lpwszLogName, -1));
					if (!bCategoryMessageFile)
						Status = ::RegSetValueEx(hk, lpwszCategoryMessageFile, 0, REG_EXPAND_SZ, reinterpret_cast<LPBYTE>(const_cast<__wchar_t*>(lpwszMsgTableFile)), static_cast<DWORD>(StrSize(lpwszMsgTableFile) + sizeof(__wchar_t)));
					if (ERROR_SUCCESS == Status)
					{
						dwValueLen = sizeof(DWORD);
						bool bCategoryCount(false);

						if (ERROR_FILE_NOT_FOUND != (Status = ::RegQueryValueExW(hk, lpwszTypesSupported, nullptr, &dwValueType, reinterpret_cast<LPBYTE>(dwValue), &dwValueLen)) && ERROR_SUCCESS == Status)
							bCategoryCount = (dwCategoryNum == dwValue);
						if (!bCategoryCount)
							Status = ::RegSetValueExW(hk, lpwszCategoryCount, 0, REG_DWORD, reinterpret_cast<LPBYTE>(&dwCategoryNum), sizeof(DWORD));
						fbChecked = ERROR_SUCCESS == Status;
					}
				}
				if (hk)
					::RegCloseKey(hk);
			}
			if (hKey)
				::RegCloseKey(hKey);
		}
	}
	return fbChecked;
}

void UnregEventSrc(__in __nullterminated __wchar_t* const lpwszLogName)
{
	HKEY hKey(nullptr);
	if (ERROR_SUCCESS == ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, lpwszEventLoggerRootKey, 0, KEY_WRITE, &hKey)) 
	{
		::RegDeleteTreeW(hKey, lpwszLogName);
		if (hKey)
			::RegCloseKey(hKey);
	}
}

void MakeReportEventRecord(__in __notnull __wchar_t* lpwszEventSrc, __in WORD wEventType, __in DWORD dwEventID, __in WORD cnInsertionsCount, __in __notnull __wchar_t** lpwszStringsToInsert)
{
	if (lpwszEventSrc)
	{
		HANDLE hEventSrc(::RegisterEventSource(nullptr, lpwszEventSrc));
		if (hEventSrc) 
		{
			::ReportEventW(hEventSrc, wEventType, 0, dwEventID, nullptr, cnInsertionsCount, 0, const_cast<const __wchar_t**>(lpwszStringsToInsert), nullptr);
			::DeregisterEventSource(hEventSrc); 
		}
	}
}

LONG WINAPI pe32smvwUnhandledExceptionFilter(__in struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	__wchar_t wszIdent[MAX_PATH] = { 0 };
	__wchar_t* lpwszDescription(nullptr);
	__wchar_t lpwszEXEName[MAX_PATH] = { 0 };
	UINT cbLen(0);
	bool fbIdentOk(false);

	HRSRC hResource(::FindResourceW(nullptr, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION));
	if (hResource)
	{
		HGLOBAL hGlobal(::LoadResource(nullptr, hResource));
		if (hGlobal)
		{
			LPVOID lpResource(::LockResource(hGlobal));
			if (lpResource)
			{
				if (::VerQueryValueW(lpResource, lpwszProductIdent, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
				{								
					::StringCchCopyNW(wszIdent, MAX_PATH, lpwszDescription, cbLen);
					fbIdentOk = true;
				}
				UnlockResource(lpResource);
			}
			::FreeResource(hGlobal);
		}
	}

	if (0 != ::GetModuleFileNameW(nullptr, lpwszEXEName, MAX_PATH) && CheckEventSrcRegistration(wszIdent, lpwszEXEName))
		MakeReportEventRecord(wszIdent, STATUS_SEVERITY_ERROR, MSG_UNHANDLED_EXCEPTION, 1, reinterpret_cast<__wchar_t**>(&lpwszEXEName));
	UnregEventSrc(wszIdent);

	return (EXCEPTION_EXECUTE_HANDLER);
	UNREFERENCED_PARAMETER(ExceptionInfo);
}

__wchar_t* GetCertificateDescription(__in __notnull PCCERT_CONTEXT pCertCtx)
{
	DWORD dwStrType(CERT_X500_NAME_STR);
	__wchar_t* szSubjectRDN(nullptr);
	HANDLE hProcessHeap(::GetProcessHeap());
	if (hProcessHeap)
	{
		DWORD dwCount(::CertGetNameStringW(pCertCtx, CERT_NAME_RDN_TYPE, 0, &dwStrType, nullptr, 0));
		if (dwCount)
		{
			szSubjectRDN = reinterpret_cast<__wchar_t*>(::HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, dwCount * sizeof(__wchar_t)));
			if (szSubjectRDN)
				::CertGetNameStringW(pCertCtx, CERT_NAME_RDN_TYPE, 0, &dwStrType, szSubjectRDN, dwCount);
		}
	}
   return szSubjectRDN;
}

bool FileExists(__in __nullterminated __wchar_t* const lpwszFileName)
{
	bool fbFileExists(false);
	HANDLE hFile(::CreateFileW(lpwszFileName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (INVALID_HANDLE_VALUE != hFile)
	{
		::CloseHandle(hFile);
		fbFileExists = true;
	}
	return (fbFileExists);
}

bool IsFileDigitallySigned(__in __nullterminated __wchar_t* const wszFilePath, __in_opt HANDLE hFile)
{
    PVOID Context;
    HANDLE FileHandle(hFile);
	BOOL fbNeedToClose(FALSE);
    DWORD HashSize(0);
    PBYTE Buffer;
    PVOID CatalogContext;
	CATALOG_INFO InfoStruct = { 0 };
	WINTRUST_DATA WintrustStructure = { 0 };
	WINTRUST_CATALOG_INFO WintrustCatalogStructure = { 0 };
	WINTRUST_FILE_INFO WintrustFileStructure = { 0 };
    __wchar_t* MemberTag;
    bool ReturnFlag(false);
    ULONG ReturnVal;
    GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	HANDLE hProcessHeap(::GetProcessHeap());
	if (!hProcessHeap)
		return false;

    //	Zero structures.

    InfoStruct.cbStruct = sizeof(CATALOG_INFO);
    WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
    WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);

    //	Get a context for signature verification.

    if (!::CryptCATAdminAcquireContext(&Context, nullptr, 0))
        return false;

    //	Open file.
	if (!FileHandle)
	{
		FileHandle = ::CreateFileW(wszFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);	// 7
		fbNeedToClose = TRUE;
	}

    if (INVALID_HANDLE_VALUE == FileHandle)
    {
            ::CryptCATAdminReleaseContext(Context, 0);
			return false;
    }

    //	Get the size we need for our hash.
    ::CryptCATAdminCalcHashFromFileHandle(FileHandle, &HashSize, nullptr, 0);
    if (HashSize == 0)
    {
            //0-sized has means error!
            ::CryptCATAdminReleaseContext(Context, 0);
			if (fbNeedToClose)
				::CloseHandle(FileHandle); 
			return false;
    }

    //	Allocate memory.
    Buffer = reinterpret_cast<PBYTE>(::HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, HashSize));

    //	Actually calculate the hash
    if (!::CryptCATAdminCalcHashFromFileHandle(FileHandle, &HashSize, Buffer, 0))
    {
            ::CryptCATAdminReleaseContext(Context, 0);
			::HeapFree(hProcessHeap, 0, Buffer);
			if (fbNeedToClose)
				::CloseHandle(FileHandle);
			return false;
    }
	   
    //	Convert the hash to a string.
    MemberTag = reinterpret_cast<PWCHAR>(::HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, ((HashSize * 2) + 1) * sizeof(__wchar_t)));
    for (unsigned int i = 0; i < HashSize; i++)
        //swprintf(&MemberTag[i * 2], L"%02X", Buffer[i]);
		::StringCchPrintfW(&MemberTag[i * 2], 3, L"%02X", Buffer[i]);

    //	Get catalog for our context.
    CatalogContext = ::CryptCATAdminEnumCatalogFromHash(Context, Buffer, HashSize, 0, nullptr);

    if (CatalogContext)
    {
            //If we couldn’t get information
        if (!::CryptCATCatalogInfoFromContext(CatalogContext, &InfoStruct, 0))
        {
            //Release the context and set the context to null so it gets picked up below.
            ::CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0); 
			CatalogContext = nullptr;
        }
    }

    //	If we have a valid context, we got our info.
    //	Otherwise, we attempt to verify the internal signature.

    if (!CatalogContext)
    {
        WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);
        WintrustFileStructure.pcwszFilePath = wszFilePath;
        WintrustFileStructure.hFile = nullptr;
        WintrustFileStructure.pgKnownSubject = nullptr;
        WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
        WintrustStructure.dwUnionChoice = WTD_CHOICE_FILE;
        WintrustStructure.pFile = &WintrustFileStructure;
        WintrustStructure.dwUIChoice = WTD_UI_NONE;
        WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;
        WintrustStructure.dwStateAction = WTD_STATEACTION_IGNORE;
        WintrustStructure.dwProvFlags = WTD_SAFER_FLAG;
        WintrustStructure.hWVTStateData = nullptr;
        WintrustStructure.pwszURLReference = nullptr;
    }
    else
    {
        //	If we get here, we have catalog info! Verify it.
        WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
        WintrustStructure.pPolicyCallbackData = 0;
        WintrustStructure.pSIPClientData = 0;
        WintrustStructure.dwUIChoice = WTD_UI_NONE;
        WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;
        WintrustStructure.dwUnionChoice = WTD_CHOICE_CATALOG;
        WintrustStructure.pCatalog = &WintrustCatalogStructure;
        WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
        WintrustStructure.hWVTStateData = nullptr;
        WintrustStructure.pwszURLReference = nullptr;
        WintrustStructure.dwProvFlags = 0;
        WintrustStructure.dwUIContext = WTD_UICONTEXT_EXECUTE;

        //	Fill in catalog info structure.
        WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
        WintrustCatalogStructure.dwCatalogVersion = 0;
        WintrustCatalogStructure.pcwszCatalogFilePath = InfoStruct.wszCatalogFile;
        WintrustCatalogStructure.pcwszMemberTag = MemberTag;
        WintrustCatalogStructure.pcwszMemberFilePath = wszFilePath;
        WintrustCatalogStructure.hMemberFile = nullptr;
    }

    //	Call our verification function.
    ReturnVal = ::WinVerifyTrust(0, &ActionGuid, &WintrustStructure);

    //	Check return.
	if (0 == ReturnVal)
		ReturnFlag = true;

    //	Free context.
    if (CatalogContext) 
		::CryptCATAdminReleaseCatalogContext(Context, CatalogContext, 0);

    //	If we successfully verified, we need to free.
    if (ReturnFlag)
    {
		WintrustStructure.dwStateAction = WTD_STATEACTION_CLOSE;
        :: WinVerifyTrust(0, &ActionGuid, &WintrustStructure);
    } 

    //	Free memory.
    ::HeapFree(hProcessHeap, 0, MemberTag);
    ::HeapFree(hProcessHeap, 0, Buffer);

	if (fbNeedToClose)
		::CloseHandle(FileHandle);

    ::CryptCATAdminReleaseContext(Context, 0);
    return ReturnFlag;
}

bool GenerateSectionName(__out_bcount(IMAGE_SIZEOF_SHORT_NAME) char* lptszUniqueSectName, __out_ecount(IMAGE_SIZEOF_SHORT_NAME) __wchar_t* lpwszUniqueSectName, __in PIMAGE_SECTION_HEADER const lpImgSectionHdr, __in WORD nNumberOfSections)
{
	char aszUniqueSectionName[IMAGE_SIZEOF_SHORT_NAME] = { 0 };
	bool fbSectionNameIsValid(false);
	//	Generate new section's name

	BYTE byIndex0('0');
	BYTE byIndex1('0');
	::CopyMemory(&aszUniqueSectionName[0], lpwszSectNamePattern, ARRAYSIZE(lpwszSectNamePattern) - 1);
	while (!fbSectionNameIsValid && (byIndex0 != 'z' && byIndex1 != 'z'))
	{
		aszUniqueSectionName[IMAGE_SIZEOF_SHORT_NAME - 2] = byIndex0;
		aszUniqueSectionName[IMAGE_SIZEOF_SHORT_NAME - 1] = byIndex1;

		if (byIndex1 != 'z')
		{
			++byIndex1;
			if (byIndex1 > '9' && byIndex1 < 'A')
				byIndex1 = 'A';
			else
				if (byIndex1 > 'Z')
					byIndex1 = 'a';
		}
		else
		{
			byIndex1 = '0';
			++byIndex0;
			if (byIndex0 > '9' && byIndex0 < 'A')
				byIndex0 = 'A';
			else
				if (byIndex0 > 'Z')
					byIndex0 = 'a';
		}
		
		bool fbIsEqual;
		for (WORD nSectIndex(0); nSectIndex < nNumberOfSections; ++nSectIndex)
		{
			fbIsEqual = true;
			for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
				if (lpImgSectionHdr[nSectIndex].Name[i] != aszUniqueSectionName[i])
				{
					fbIsEqual = false;
					break;
				}
			if (!fbIsEqual)
				break;
		}
		fbSectionNameIsValid = !fbIsEqual;
	}

	if (fbSectionNameIsValid)
	{
		for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
			if (aszUniqueSectionName[i])
			{
				lptszUniqueSectName[i] = aszUniqueSectionName[i];
				lpwszUniqueSectName[i] = MapChar(aszUniqueSectionName[i]);
			}
			else
				break;
	}

	return (fbSectionNameIsValid);
}

//	Check the uniqueness of the section's name
bool IsSectionNameUnique(__in_bcount(IMAGE_SIZEOF_SHORT_NAME) __notnull char* lptszUniqueSectName, __in __notnull PIMAGE_SECTION_HEADER const lpImgSectionHdr, __in WORD nNumberOfSections)
{
	bool fbUnique(false);
	if (lptszUniqueSectName && lpImgSectionHdr && nNumberOfSections)
	{
		bool fbEqual(true);
		fbUnique = true;
		for (WORD nSectIndex(0); nSectIndex < nNumberOfSections; ++nSectIndex)
		{
			int nCharIndex(0);
			fbEqual = true;

			//	Compare chars ...
			while (nCharIndex < IMAGE_SIZEOF_SHORT_NAME && fbEqual)
			{
				if (lpImgSectionHdr[nSectIndex].Name[nCharIndex] != lptszUniqueSectName[nCharIndex])
					fbEqual = false;
				++nCharIndex;
			}

			if (fbEqual)
			{
				fbUnique = false;
				break;
			}
		}
	}
	return fbUnique;
}

bool AddDataSection(__in __notnull HANDLE hFile, __in __notnull LPVOID const lpImageBase, __in __notnull HANDLE hStdOut)
{
	bool fbCompleted(false);

	LPVOID lpFileBase(const_cast<LPVOID>(lpImageBase));
	PIMAGE_DOS_HEADER lpImgDOSHdr(reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileBase));
	PIMAGE_NT_HEADERS lpImgNTHdrs(reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<UINT_PTR>(lpImgDOSHdr) + lpImgDOSHdr ->e_lfanew));
	PIMAGE_FILE_HEADER lpImgFileHdr(&lpImgNTHdrs ->FileHeader);
	PIMAGE_OPTIONAL_HEADER lpImgOptHdr(&lpImgNTHdrs ->OptionalHeader);
	PIMAGE_SECTION_HEADER lpImgSectionHdr(IMAGE_FIRST_SECTION(lpImgNTHdrs));
	PIMAGE_SECTION_HEADER pNewSection(nullptr);
	LARGE_INTEGER liFileSize = { 0 };
	LARGE_INTEGER liDataFileSize = { 0 };
	__wchar_t szNewLine[3] = { L'\r', L'\n', 0	};

	HANDLE hDataFile(::CreateFileW(g_wszFileName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0));
	if (INVALID_HANDLE_VALUE == hDataFile || !::GetFileSizeEx(hDataFile, &liDataFileSize))
	{
		ShowSysErrorMsg(::GetLastError(), hStdOut);
		if (INVALID_HANDLE_VALUE != hDataFile)
			::CloseHandle(hDataFile);
		return fbCompleted;
	}

	DWORD dwAlignedDataSize((liDataFileSize.LowPart + lpImgOptHdr ->FileAlignment - 1) & ~(lpImgOptHdr ->FileAlignment - 1));

	HANDLE hDataFileMap(::CreateFileMappingW(hDataFile, nullptr, PAGE_READONLY, 0, 0, nullptr));
	if (!hDataFileMap)
	{
		ShowSysErrorMsg(::GetLastError(), hStdOut);
		::CloseHandle(hDataFile);
		return fbCompleted;
	}
	LPVOID lpDataFileBase(::MapViewOfFile(hDataFileMap, FILE_MAP_READ , 0, 0, 0));
	if (!lpFileBase)
	{
		ShowSysErrorMsg(::GetLastError(), hStdOut);
		::CloseHandle(hDataFileMap);
		::CloseHandle(hDataFile);
		return fbCompleted;
	}

	if (!::GetFileSizeEx(hFile, &liFileSize))
		ShowSysErrorMsg(::GetLastError(), hStdOut);
	else
	{
		UINT_PTR nEmptySlot(reinterpret_cast<UINT_PTR>(&lpImgSectionHdr[lpImgFileHdr ->NumberOfSections]) - reinterpret_cast<UINT_PTR>(lpFileBase));
		if ((nEmptySlot + sizeof(IMAGE_SECTION_HEADER)) < static_cast<UINT_PTR>(lpImgOptHdr ->SizeOfHeaders))
		{
			pNewSection = &lpImgSectionHdr[lpImgFileHdr ->NumberOfSections];
			//	If section name is passed - check whether it is unique ?
			bool fbSectionNameIsValid(false);															
			if (g_fbFileSectionNamePassed)
			{
				bool fbIsEqual(false);
				for (WORD nSectIndex(0); nSectIndex < lpImgFileHdr ->NumberOfSections; ++nSectIndex)
				{
					fbIsEqual = true;
					for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
						if (lpImgSectionHdr[nSectIndex].Name[i] != g_acNativeFileSectionName[i])
						{
							fbIsEqual = false;
							break;
						}
					if (fbIsEqual)
						break;
				}
				fbSectionNameIsValid = !fbIsEqual;
			}
			else
				//	Generate new section's name
				fbSectionNameIsValid = GenerateSectionName(g_acNativeFileSectionName, g_awcFileNativeSectionName, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);

			if (fbSectionNameIsValid)
			{
				if (!g_fbFileSectionNamePassed)
				{
					ShowResourceStringArgs(hStdOut, IDS_MSG_DATA_SECTION_NAME_GENERATED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_awcFileNativeSectionName[0]);
					g_fbFileSectionNamePassed = true;
				}

				IMAGE_SECTION_HEADER ish = { 0 };
				//	Fill the structure ...
				::CopyMemory(&ish.Name[0], &g_acNativeFileSectionName[0], IMAGE_SIZEOF_SHORT_NAME);
				DWORD dwVirtualSize(g_nSectionSize);
				if (g_fbPageUnits)
				{
					SYSTEM_INFO si = { 0 };
					::GetSystemInfo(&si);
					dwVirtualSize *= si.dwPageSize;
				}
				ish.Misc.VirtualSize = (dwVirtualSize + (lpImgOptHdr ->SectionAlignment - 1)) & (~(lpImgOptHdr ->SectionAlignment - 1));

				//	Calculate section's virtual address & PointerToRawData
				DWORD dwVirtualAddress(0);
				DWORD dwSectionsFinish(0);
				DWORD dwPointerToData(0);

				for (WORD nSectIndex(0); nSectIndex < lpImgFileHdr ->NumberOfSections; ++nSectIndex)
				{
					if (dwSectionsFinish < (lpImgSectionHdr[nSectIndex].PointerToRawData + lpImgSectionHdr[nSectIndex].SizeOfRawData))
						dwSectionsFinish = lpImgSectionHdr[nSectIndex].PointerToRawData + lpImgSectionHdr[nSectIndex].SizeOfRawData;
					if (dwPointerToData < dwSectionsFinish)
						dwPointerToData = dwSectionsFinish;

					DWORD dwNextSectionA(lpImgSectionHdr[nSectIndex].VirtualAddress + lpImgSectionHdr[nSectIndex].Misc.VirtualSize);
					dwNextSectionA = (dwNextSectionA + (lpImgOptHdr ->SectionAlignment - 1)) & (~(lpImgOptHdr ->SectionAlignment - 1));
					if (dwVirtualAddress < dwNextSectionA)
						dwVirtualAddress = dwNextSectionA;
				}

				ish.VirtualAddress = dwVirtualAddress;
				ish.PointerToRawData = dwPointerToData;
				ish.SizeOfRawData = dwAlignedDataSize;
				ish.Misc.VirtualSize = liDataFileSize.LowPart;
				ish.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

				::CopyMemory(pNewSection, &ish, sizeof(IMAGE_SECTION_HEADER));
				lpImgFileHdr ->NumberOfSections++;
				lpImgOptHdr ->SizeOfImage += (ish.Misc.VirtualSize + (lpImgOptHdr ->SectionAlignment - 1)) & (~(lpImgOptHdr ->SectionAlignment - 1));
				lpImgOptHdr ->CheckSum = 0;

				LARGE_INTEGER liFilePtr = { 0 };
				LARGE_INTEGER liOriginalFilePtr;
				liFilePtr.LowPart = dwPointerToData;
				if (::SetFilePointerEx(hFile, liFilePtr, &liOriginalFilePtr, FILE_BEGIN))
				{
					DWORD dwWritten(0);
					if (::WriteFile(hFile, lpDataFileBase, dwAlignedDataSize, &dwWritten, nullptr) && (dwWritten == dwAlignedDataSize))
					{
						if (!::FlushViewOfFile(lpFileBase, 0))
							ShowSysErrorMsg(::GetLastError(), hStdOut);
						else
						{
							ShowResourceString(hStdOut, IDS_MSG_COMPLETED_DATA, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							unsigned __int64* lpTag(reinterpret_cast<unsigned __int64*>(&ish.Name[0]));
							ShowResourceStringArgs(hStdOut, IDS_MSG_TAG_VALUE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), *lpTag, &g_awcFileNativeSectionName[0]);
							ShowString(hStdOut, szNewLine);
							fbCompleted = true;
						}
					}
					else
					{
						ShowSysErrorMsg(::GetLastError(), hStdOut);
					}
				}
				else
					ShowSysErrorMsg(::GetLastError(), hStdOut);
			}
			else
			{
				//	Unable to generate new section name
				if (g_fbFileSectionNamePassed)
					ShowResourceStringArgs(hStdOut, IDS_ERROR_SECTION_EXISTS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_awcFileNativeSectionName[0]);
				else
					ShowResourceString(hStdOut, IDS_ERROR_UNABLE_GENERATE_SECTION_NAME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
				ShowString(hStdOut, szNewLine);
			}
		}
		else
		{
			//	Not enough space for new section descriptor
			ShowResourceString(hStdOut, IDS_ERROR_NO_EMPTY_SECTION_DESCRIPTOR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			ShowString(hStdOut, szNewLine);
		}
	}

	if (lpDataFileBase)
		::UnmapViewOfFile(lpDataFileBase);
	if (hDataFileMap)
		::CloseHandle(hDataFileMap);
	if (INVALID_HANDLE_VALUE != hDataFile)
		::CloseHandle(hDataFile);

	return fbCompleted;
}

bool AddVirtualSection(__in __notnull LPVOID const lpImageBase, __in __notnull HANDLE hStdOut, __in LARGE_INTEGER liFileSize)
{
	PIMAGE_SECTION_HEADER pNewSection(nullptr);
	LPVOID lpFileBase(const_cast<LPVOID>(lpImageBase));
	PIMAGE_DOS_HEADER lpImgDOSHdr(reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileBase));
	PIMAGE_NT_HEADERS lpImgNTHdrs(reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<UINT_PTR>(lpImgDOSHdr) + lpImgDOSHdr ->e_lfanew));
	PIMAGE_FILE_HEADER lpImgFileHdr(&lpImgNTHdrs ->FileHeader);
	PIMAGE_OPTIONAL_HEADER lpImgOptHdr(&lpImgNTHdrs ->OptionalHeader);
	PIMAGE_SECTION_HEADER lpImgSectionHdr(IMAGE_FIRST_SECTION(lpImgNTHdrs));

	__wchar_t szNewLine[3] = { L'\r', L'\n', 0	};

	bool fbCompleted(false);

	UINT_PTR nEmptySlot(reinterpret_cast<UINT_PTR>(&lpImgSectionHdr[lpImgFileHdr ->NumberOfSections]) - reinterpret_cast<UINT_PTR>(lpFileBase));
	if ((nEmptySlot + sizeof(IMAGE_SECTION_HEADER)) < static_cast<UINT_PTR>(lpImgOptHdr ->SizeOfHeaders))
	{
		pNewSection = &lpImgSectionHdr[lpImgFileHdr ->NumberOfSections];
		//	If section name is passed - check whether it is unique ?
		bool fbSectionNameIsValid(false);															
		if (g_fbSectionNamePassed)
		{
			bool fbIsEqual(false);
			for (WORD nSectIndex(0); nSectIndex < lpImgFileHdr ->NumberOfSections; ++nSectIndex)
			{
				fbIsEqual = true;
				for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
					if (lpImgSectionHdr[nSectIndex].Name[i] != g_acNativeSectionName[i])
					{
						fbIsEqual = false;
						break;
					}
				if (fbIsEqual)
					break;
			}
			fbSectionNameIsValid = !fbIsEqual;
		}
		else
			//	Generate new section's name
			fbSectionNameIsValid = GenerateSectionName(g_acNativeSectionName, g_awcNativeSectionName, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);

		if (fbSectionNameIsValid)
		{
			if (!g_fbSectionNamePassed)
			{
				ShowResourceStringArgs(hStdOut, IDS_MSG_SECTION_NAME_GENERATED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_awcNativeSectionName[0]);
				g_fbSectionNamePassed = true;
			}

			IMAGE_SECTION_HEADER ish = { 0 };
			//	Fill the structure ...
			::CopyMemory(&ish.Name[0], &g_acNativeSectionName[0], IMAGE_SIZEOF_SHORT_NAME);
			DWORD dwVirtualSize(g_nSectionSize);
			if (g_fbPageUnits)
			{
				SYSTEM_INFO si = { 0 };
				::GetSystemInfo(&si);
				dwVirtualSize *= si.dwPageSize;
			}
			ish.Misc.VirtualSize = (dwVirtualSize + (lpImgOptHdr ->SectionAlignment - 1)) & (~(lpImgOptHdr ->SectionAlignment - 1));

			//	Calculate section's virtual address & PointerToRawData
			DWORD dwVirtualAddress(0);
			DWORD dwSectionsFinish(0);

			for (WORD nSectIndex(0); nSectIndex < lpImgFileHdr ->NumberOfSections; ++nSectIndex)
			{
				if (dwSectionsFinish < (lpImgSectionHdr[nSectIndex].PointerToRawData + lpImgSectionHdr[nSectIndex].SizeOfRawData))
					dwSectionsFinish = lpImgSectionHdr[nSectIndex].PointerToRawData + lpImgSectionHdr[nSectIndex].SizeOfRawData;

				DWORD dwNextSectionA(lpImgSectionHdr[nSectIndex].VirtualAddress + lpImgSectionHdr[nSectIndex].Misc.VirtualSize);
				dwNextSectionA = (dwNextSectionA + (lpImgOptHdr ->SectionAlignment - 1)) & (~(lpImgOptHdr ->SectionAlignment - 1));
				if (dwVirtualAddress < dwNextSectionA)
					dwVirtualAddress = dwNextSectionA;
			}

			ish.VirtualAddress = dwVirtualAddress;
			ish.Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

			::CopyMemory(pNewSection, &ish, sizeof(IMAGE_SECTION_HEADER));
			lpImgFileHdr ->NumberOfSections++;
			lpImgOptHdr ->SizeOfImage += ish.Misc.VirtualSize;
			lpImgOptHdr ->CheckSum = 0;

			//"d:\VCPP\2017\TestPE32\Debug\TestPE32.EXE" -v -a:.XData0=16p
			DWORD dwHeaderSum(0), dwCheckSum(0);
			if (::CheckSumMappedFile(lpFileBase, liFileSize.LowPart, &dwHeaderSum, &dwCheckSum))
			{
				lpImgOptHdr ->CheckSum = dwCheckSum;
				if (!::FlushViewOfFile(lpFileBase, 0))
					ShowSysErrorMsg(::GetLastError(), hStdOut);
				else
				{
					ShowResourceString(hStdOut, IDS_MSG_COMPLETED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
					unsigned __int64* lpTag(reinterpret_cast<unsigned __int64*>(&ish.Name[0]));
					ShowResourceStringArgs(hStdOut, IDS_MSG_TAG_VALUE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), *lpTag, &g_awcNativeSectionName[0]);
					ShowString(hStdOut, szNewLine);
					fbCompleted = true;
				}
			}
			else
				ShowSysErrorMsg(::GetLastError(), hStdOut);
		}
		else
		{
			//	Unable to generate new section name
			if (g_fbFileSectionNamePassed)
				ShowResourceStringArgs(hStdOut, IDS_ERROR_SECTION_EXISTS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_awcNativeSectionName[0]);
			else
				ShowResourceString(hStdOut, IDS_ERROR_UNABLE_GENERATE_SECTION_NAME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
			ShowString(hStdOut, szNewLine);
		}
	}
	else
	{
		//	Not enough space for new section descriptor
		ShowResourceString(hStdOut, IDS_ERROR_NO_EMPTY_SECTION_DESCRIPTOR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		ShowString(hStdOut, szNewLine);
	}
	return (fbCompleted);
}

void ShowTargetSection(__in __notnull HANDLE hStdOut, __in DWORD dwDataNameMsgID, __in DWORD dwDataPtr, __in __notnull PIMAGE_SECTION_HEADER const lpImgSectionHdr, __in WORD nNumberOfSections)
{
	WORD nTargetSectionNumber;
	bool fbSectFound(false);
	if (dwDataNameMsgID)
		ShowResourceString(hStdOut, dwDataNameMsgID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
	for (WORD nSectIndex(0); nNumberOfSections; ++nSectIndex)
		if (dwDataPtr >= lpImgSectionHdr[nSectIndex].VirtualAddress && dwDataPtr < (lpImgSectionHdr[nSectIndex].VirtualAddress + lpImgSectionHdr[nSectIndex].Misc.VirtualSize))
		{
			nTargetSectionNumber = nSectIndex;
			fbSectFound = true;
			break;
		}

	if (fbSectFound)
	{
		__wchar_t awcSectName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };

		for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
			if (lpImgSectionHdr[nTargetSectionNumber].Name[i])
				awcSectName[i] = MapChar(lpImgSectionHdr[nTargetSectionNumber].Name[i]);
			else
				break;

		ShowResourceStringArgs(hStdOut, IDS_MSG_TARGER_SECTION, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &awcSectName[0]);
	}
	else
		ShowResourceString(hStdOut, IDS_MSG_SECT_NOT_FOUND, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
}

int __cdecl wmain(int argc, __wchar_t* argv[])
{
	int nRetCode(0);
	LARGE_INTEGER liFileSize = { 0 };

	::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
	LPTOP_LEVEL_EXCEPTION_FILTER lpEFOriginal(::SetUnhandledExceptionFilter(pe32smvwUnhandledExceptionFilter));

	HANDLE hOut(::GetStdHandle(STD_OUTPUT_HANDLE));
	//HANDLE hProcessHeap(::GetProcessHeap());

	__wchar_t szOutStrHeader[MAX_PATH] = { 0 };
	__wchar_t szOutStrVersion[MAX_PATH] = { 0 };
	__wchar_t szNewLine[3] = { L'\r', L'\n', 0	};
	__wchar_t szOldTitle[MAX_PATH] = { 0 };

	bool fbHeaderOk(false);
	bool fbVersionOk(false);
	bool fbIdentOk(false);
	bool fbReportEvent(false);
	bool fbTitleChanged(false);

	if (hOut/* && hProcessHeap*/)
	{
		__wchar_t* lpwszDescription(nullptr);
		UINT cbLen(0);

		HRSRC hResource(::FindResourceW(nullptr, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION));
		if (hResource)
		{
			HGLOBAL hGlobal(::LoadResource(nullptr, hResource));
			if (hGlobal)
			{
				LPVOID lpResource(::LockResource(hGlobal));
				if (lpResource)
				{
					if (::VerQueryValueW(lpResource, lpwszFileDescription, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
						fbHeaderOk = SUCCEEDED(::StringCchCopyW(szOutStrHeader, MAX_PATH, lpwszDescription));

					__wchar_t* lpwszVersion(LoadStringEx(::GetModuleHandleW(nullptr), IDS_VERSION_STRING, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)));
					if (lpwszVersion)
					{
						if (SUCCEEDED(::StringCchCopyW(szOutStrVersion, MAX_PATH, lpwszVersion)))
						{	
							if (::VerQueryValueW(lpResource, lpwszFileVersion, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
							{
								::StringCchCatW(szOutStrVersion, MAX_PATH, lpwszDescription);
								::StringCchCatW(szOutStrVersion, MAX_PATH, szNewLine);
							}
							if (::VerQueryValueW(lpResource, lpwszLegalCopyright, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
							{
								::StringCchCatW(szOutStrVersion, MAX_PATH, lpwszDescription);
								::StringCchCatW(szOutStrVersion, MAX_PATH, szNewLine);
							}
							fbVersionOk = true;
							if (::VerQueryValueW(lpResource, lpwszProductIdent, reinterpret_cast<LPVOID*>(&lpwszDescription), &cbLen))
							{								
								::StringCchCopyNW(g_wszIdent, MAX_PATH, lpwszDescription, cbLen);
								fbIdentOk = true;
							}
						}
						ReleaseLoadedString(lpwszVersion);
					}
					UnlockResource(lpResource);
				}
				::FreeResource(hGlobal);
			}
		}

		fbReportEvent = fbIdentOk ? CheckEventSrcRegistration(g_wszIdent, argv[0]) : false;

		if (fbHeaderOk)
		{
			if (::GetConsoleTitleW(szOldTitle, ARRAYSIZE(szOldTitle)) && ::SetConsoleTitleW(szOutStrHeader))
				fbTitleChanged = true;

			ShowString(hOut, szOutStrHeader);
			ShowString(hOut, szNewLine);

			if (fbVersionOk)
			{
				ShowString(hOut, szOutStrVersion);
				ShowString(hOut, szNewLine);
			}

			if (argc <= 2)
			{
				ShowUsage(hOut);
				ShowString(hOut, szNewLine);
				nRetCode = ERROR_TOO_FEW_ARGS;		//	Too few arguments
			}
			else
			{
				if (FileExists(argv[1]))
				{
					ShowResourceStringArgs(hOut, IDS_TARGET_FILE_NAME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), ::PathFindFileNameW(argv[1]));
					ShowString(hOut, szNewLine);

					if (false == (g_fbOptionsAreCorrect = CheckOptArguments(argc - 2, &argv[2])) || (g_fbAdd && g_fbFileAdd)) // Prevent simultaneously adding of 2 sections
					{
						if (!(g_fbAdd && g_fbFileAdd))
						{
							g_nInvalidOptNo += 2;
							ShowString(hOut, argv[g_nInvalidOptNo]);
							ShowString(hOut, szNewLine);
							for (int c(0); c < g_nInvalidCharIndex; ++c)
								ShowString(hOut, L" ");
							ShowResourceStringEx(hOut, IDS_ERROR_INVALID_OPT_KEY, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
							ShowString(hOut, szNewLine);
						}
						else
						{
							ShowResourceStringEx(hOut, IDS_ERROR_UNABLE_PROC_ARGS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
							ShowString(hOut, szNewLine);
						}

						ShowUsage(hOut);
						ShowString(hOut, szNewLine);
						nRetCode = ERROR_INVALID_OPTION_KEY;		//	Invalid option key
					}
					else
					{
						if (0 == StrLen(g_wszSectionName))
							g_fbSectionNamePassed = false;
						if (0 == StrLen(g_wszFileSectionName))
							g_fbFileSectionNamePassed = false;
						if (0 == StrLen(g_wszFileName))
							g_fbDataFileNamePassed = false;
						if (g_fbVerbose)
							ShowResourceString(hOut, IDS_MSG_VERBOSE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

						if (g_fbAdd && g_fbVerbose)
						{
							ShowResourceString(hOut, IDS_MSG_ADD_SECTION, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							if (g_fbSectionNamePassed)
								ShowResourceStringArgs(hOut, g_fbPageUnits ? IDS_MSG_ADD_SECTION_NAME_SIZE_P : IDS_MSG_ADD_SECTION_NAME_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), g_wszSectionName, g_nSectionSize);
							else
								ShowResourceStringArgs(hOut, g_fbPageUnits ? IDS_MSG_ADD_SECTION_SIZE_P : IDS_MSG_ADD_SECTION_SIZE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), g_nSectionSize);
							ShowString(hOut, szNewLine);
						}

						if (g_fbFileAdd && g_fbVerbose)
						{
							ShowResourceString(hOut, IDS_MSG_ADD_FILE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							if (g_fbDataFileNamePassed)
								ShowResourceStringArgs(hOut, IDS_MSG_ADD_DATA_SECTION_NAME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_wszFileSectionName[0]);
							ShowResourceStringArgs(hOut, IDS_MSG_ADD_FILE_NAME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_wszFileName[0]);
							ShowString(hOut, szNewLine);
						}

						if (g_fbVerbose)
						{
							bool fbAdmin(false);
							if (true == (fbAdmin = IsUserAdmin()))
								ShowResourceString(hOut, IDS_UNDERADMIN_STRING, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

							TOKEN_ELEVATION_TYPE tet(static_cast<TOKEN_ELEVATION_TYPE>(0));
							if (TokenElevationTypeFull == (tet = GetElevationType()))
								ShowResourceString(hOut, IDS_ELEVATED_STRING, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
							if (fbAdmin || (TokenElevationTypeFull == tet))
								ShowString(hOut, szNewLine);
						}

						if (!CanAccessFile(argv[1], (g_fbAdd || g_fbFileAdd) ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ))
						{
							ShowResourceStringEx(hOut, IDS_MSG_FILE_ACCESS_DENIED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
							ShowString(hOut, szNewLine);
							nRetCode = ERROR_FILE_ACCESS_FAILED;		//	Access denied.
						}
						else
						{
							if (true == (g_fbDigSig = IsFileDigitallySigned(argv[1], nullptr)))
							{
								ShowResourceString(hOut, IDS_MSG_FILE_SIGNED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
								if (g_fbDigSig && (g_fbAdd || g_fbFileAdd))
								{
									CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
									BOOL fbRestoreAttr(::GetConsoleScreenBufferInfo(hOut, &csbi));
									if (fbRestoreAttr)
										::SetConsoleTextAttribute(hOut, FOREGROUND_INTENSITY | FOREGROUND_RED);
									ShowResourceString(hOut, IDS_MSG_ADD_ON_SIGNED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
									if (fbRestoreAttr)
										::SetConsoleTextAttribute(hOut, csbi.wAttributes);
									g_fbAdd = false;
									g_fbFileAdd = false;
								}
							}

							HANDLE hFile(::CreateFileW(argv[1], (g_fbAdd || g_fbFileAdd) ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0));
							if (INVALID_HANDLE_VALUE == hFile || !::GetFileSizeEx(hFile, &liFileSize))
							{									
								ShowSysErrorMsg(::GetLastError(), hOut);
								if (INVALID_HANDLE_VALUE != hFile)
									::CloseHandle(hFile);
								nRetCode = ERROR_FILE_ACCESS_FAILED;		//	Unable to open file or obtain file size 
							}
							else
							{
								if (g_fbDigSig)
								{
									GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
									WINTRUST_FILE_INFO sWintrustFileInfo = { 0 };
									WINTRUST_DATA      sWintrustData = { 0 };

									sWintrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
									sWintrustFileInfo.pcwszFilePath = argv[1];
									sWintrustFileInfo.hFile = hFile;

									sWintrustData.cbStruct            = sizeof(WINTRUST_DATA);
									sWintrustData.dwUIChoice          = WTD_UI_NONE;
									sWintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
									sWintrustData.dwUnionChoice       = WTD_CHOICE_FILE;
									sWintrustData.pFile               = &sWintrustFileInfo;
									sWintrustData.dwStateAction       = WTD_STATEACTION_VERIFY;

									HRESULT hr(::WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData));
									if (SUCCEEDED(hr))
									{
										// retreive the signer certificate and display its information
										CRYPT_PROVIDER_DATA const *psProvData(nullptr);
										CRYPT_PROVIDER_SGNR       *psProvSigner(nullptr);
										CRYPT_PROVIDER_CERT       *psProvCert(nullptr);
										FILETIME                   localFt = { 0 };
										SYSTEMTIME                 sysTime = { 0 };

										psProvData = ::WTHelperProvDataFromStateData(sWintrustData.hWVTStateData);
										if (psProvData)
										{
											psProvSigner = WTHelperGetProvSignerFromChain(const_cast<PCRYPT_PROVIDER_DATA>(psProvData), 0 , FALSE, 0);
											if (psProvSigner && g_fbVerbose)
											{
												::FileTimeToLocalFileTime(&psProvSigner->sftVerifyAsOf, &localFt);
												::FileTimeToSystemTime(&localFt, &sysTime);

												ShowResourceStringArgs(hOut, IDS_IMG_SIGNATURE_DATETIME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), sysTime.wDay, sysTime.wMonth,sysTime.wYear, sysTime.wHour,sysTime.wMinute,sysTime.wSecond);

												if (psProvSigner ->csCertChain)
												{
													if (1 == psProvSigner ->csCertChain)
														ShowResourceString(hOut, IDS_IMG_FILE_SIGNER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
													else
														ShowResourceString(hOut, IDS_IMG_FILE_SIGNERS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

													for (DWORD dwCertIndex(0); dwCertIndex < psProvSigner ->csCertChain; ++dwCertIndex)
													{
														psProvCert = ::WTHelperGetProvCertFromChain(psProvSigner, dwCertIndex);
														if (psProvCert)
														{
															__wchar_t* szCertDesc(::GetCertificateDescription(psProvCert->pCert));
															if (szCertDesc)
															{
																ShowString(hOut, szCertDesc);
																ShowString(hOut, szNewLine);
																DISPOSE_BUF(&szCertDesc)
															}
														}
													}
													ShowString(hOut, szNewLine);
												}

												if (psProvSigner->csCounterSigners && g_fbVerbose)
												{
													// retreive timestamp information
													::FileTimeToLocalFileTime(&psProvSigner->pasCounterSigners[0].sftVerifyAsOf, &localFt);
													::FileTimeToSystemTime(&localFt, &sysTime);

													ShowResourceStringArgs(hOut, IDS_IMG_TIMESTAMP_DATETIME, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), sysTime.wDay, sysTime.wMonth,sysTime.wYear, sysTime.wHour,sysTime.wMinute,sysTime.wSecond);

													if (psProvSigner->csCounterSigners)
													{
														if (1 == psProvSigner->csCounterSigners)
															ShowResourceString(hOut, IDS_IMG_TIMESTAMP_SIGNER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
														else
															ShowResourceString(hOut, IDS_IMG_TIMESTAMP_SIGNERS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

														for (DWORD idxCert(0); idxCert < psProvSigner->csCounterSigners; ++idxCert)
														{
															psProvCert = ::WTHelperGetProvCertFromChain(&psProvSigner->pasCounterSigners[idxCert], idxCert);
															if (psProvCert)
															{
																__wchar_t* szCertDesc = ::GetCertificateDescription(psProvCert->pCert);
																if (szCertDesc)
																{
																	ShowString(hOut, szCertDesc);
																	ShowString(hOut, szNewLine);
																	DISPOSE_BUF(szCertDesc)
																}
															}
														}
														ShowString(hOut, szNewLine);
													}
												}
											}
										}
										g_fbDigSigIsValid = true;
									}
									else
									{
										switch(hr)
										{
										case TRUST_E_BAD_DIGEST:
											ShowResourceString(hOut, IDS_MSG_FILE_BAD_SIG, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
											break;
										case TRUST_E_PROVIDER_UNKNOWN:
											ShowResourceString(hOut, IDS_MSG_FILE_SIG_PROV_UNK, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
											break;
										case TRUST_E_SUBJECT_NOT_TRUSTED:
											ShowResourceString(hOut, IDS_MSG_FILE_SIG_NOT_TRUSTED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
											break;
										default:
											ShowResourceStringArgs(hOut, IDS_MSG_FILE_SIG_ERROR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), hr);
											break;
										}
										ShowString(hOut, szNewLine);
									}
								}

								if (g_fbDigSig && g_fbDigSigIsValid)
								{
									ShowResourceString(hOut, IDS_MSG_FILE_SIG_OK, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
									ShowString(hOut, szNewLine);
								}

								HANDLE hFileMap(::CreateFileMappingW(hFile, nullptr, (g_fbAdd || g_fbFileAdd) ? PAGE_READWRITE : PAGE_READONLY, 0, 0, nullptr));
								if (!hFileMap)
								{
									ShowSysErrorMsg(::GetLastError(), hOut);
									::CloseHandle(hFile);
									nRetCode = ERROR_UNABLE_MAP_FILE;		//	Unable to map file
								}
								else
								{
									LPVOID lpFileBase(::MapViewOfFile(hFileMap, (g_fbAdd || g_fbFileAdd) ? FILE_MAP_READ | FILE_MAP_WRITE : FILE_MAP_READ , 0, 0, 0));
									if (!lpFileBase)
									{
										ShowSysErrorMsg(::GetLastError(), hOut);
										::CloseHandle(hFileMap);
										::CloseHandle(hFile);
										nRetCode = ERROR_MAP_VIEW_CREATE_FAILED;		//	Unable to create view of map file
									}
									else
									{
										//	Convert and copy section name to buffer
										if (g_fbAdd || g_fbFileAdd)
										{
											if (g_fbSectionNamePassed)
											{
												for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
												{
													if (g_wszSectionName[i])
													{
														g_acNativeSectionName[i] = MapWChar(g_wszSectionName[i]);
														g_awcNativeSectionName[i] = g_wszSectionName[i];
													}
													else
														break;
												}

												size_t nSectNameSize(StrLen(&g_wszSectionName[0]));
												if (IMAGE_SIZEOF_SHORT_NAME < nSectNameSize && g_fbVerbose)
												{
													ShowResourceString(hOut, IDS_MSG_SECTION_NAME_TRUNCATED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
													for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
														if (g_acNativeSectionName[i])
															ShowChar(hOut, g_acNativeSectionName[i]);
														else
															break;
													ShowString(hOut, szNewLine);
												}
											}

											if (g_fbFileSectionNamePassed)
											{
												for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
												{
													if (g_wszFileSectionName[i])
													{
														g_acNativeFileSectionName[i] = MapWChar(g_wszFileSectionName[i]);
														g_awcFileNativeSectionName[i] = g_wszFileSectionName[i];
													}
													else
														break;
												}

												size_t nFileSectNameSize(StrLen(&g_wszFileSectionName[0]));
												if (IMAGE_SIZEOF_SHORT_NAME < nFileSectNameSize && g_fbVerbose)
												{
													ShowResourceString(hOut, IDS_MSG_FILE_SECTION_NAME_TRUNCATED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
													for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
														if (g_acNativeFileSectionName[i])
															ShowChar(hOut, g_acNativeFileSectionName[i]);
														else
															break;
													ShowString(hOut, szNewLine);
												}
											}
										}

										PIMAGE_DOS_HEADER lpImgDOSHdr(reinterpret_cast<PIMAGE_DOS_HEADER>(lpFileBase));

										if ((lpImgDOSHdr ->e_magic != IMAGE_DOS_SIGNATURE) || (lpImgDOSHdr ->e_lfarlc != 0x40))
										{
											nRetCode = ERROR_DOS_STUB_IS_INVALID;		//	DOS stub is damaged
											ShowResourceStringEx(hOut, IDS_MSG_DOS_HDR_INVALID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
										}
										else
										{
											PIMAGE_NT_HEADERS lpImgNTHdrs(reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<UINT_PTR>(lpImgDOSHdr) + lpImgDOSHdr ->e_lfanew));
											if (lpImgNTHdrs ->Signature != IMAGE_NT_SIGNATURE)
											{
												nRetCode = ERROR_PE_HEADERS_ARE_INVALID;		//	PE headers are damaged
												ShowResourceStringEx(hOut, IDS_MSG_NT_PE_INVALID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
											}
											else
											{
												PIMAGE_FILE_HEADER lpImgFileHdr(&lpImgNTHdrs ->FileHeader);
												g_wNumberOfSections = lpImgFileHdr ->NumberOfSections;
												
												PIMAGE_OPTIONAL_HEADER lpImgOptHdr(&lpImgNTHdrs ->OptionalHeader);

												if (IMAGE_FILE_MACHINE_I386 == lpImgFileHdr ->Machine && IMAGE_NT_OPTIONAL_HDR32_MAGIC == lpImgOptHdr ->Magic)
												{
													PIMAGE_DATA_DIRECTORY lpImgDataDir(&lpImgOptHdr ->DataDirectory[0]);
													PIMAGE_SECTION_HEADER lpImgSectionHdr(IMAGE_FIRST_SECTION(lpImgNTHdrs));

													//	Show sections
													ShowResourceString(hOut, IDS_MSG_SECT_FORMAT_HEADER, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));

													for (WORD nSectIndex(0); nSectIndex < lpImgFileHdr ->NumberOfSections; ++nSectIndex)
													{
														__wchar_t awcSectName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };

														for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
															if (lpImgSectionHdr[nSectIndex].Name[i])
																awcSectName[i] = MapChar(lpImgSectionHdr[nSectIndex].Name[i]);
															else
																break;

														DWORD dwNextSectionVA(lpImgSectionHdr[nSectIndex].PointerToRawData + lpImgSectionHdr[nSectIndex].SizeOfRawData);
														dwNextSectionVA = (dwNextSectionVA + (lpImgOptHdr ->FileAlignment - 1)) & (~(lpImgOptHdr ->FileAlignment - 1));

														DWORD dwNextSectionA(lpImgSectionHdr[nSectIndex].VirtualAddress + lpImgSectionHdr[nSectIndex].Misc.VirtualSize);
														dwNextSectionA = (dwNextSectionA + (lpImgOptHdr ->SectionAlignment - 1)) & (~(lpImgOptHdr ->SectionAlignment - 1));

														if (lpImgSectionHdr[nSectIndex].SizeOfRawData)
															ShowResourceStringArgs(hOut, IDS_MSG_SECT_FORMAT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), nSectIndex + 1, &awcSectName[0], lpImgSectionHdr[nSectIndex].PointerToRawData, dwNextSectionVA, 
																lpImgSectionHdr[nSectIndex].VirtualAddress, dwNextSectionA, lpImgSectionHdr[nSectIndex].SizeOfRawData, lpImgSectionHdr[nSectIndex].Misc.VirtualSize/*dwNextSectionA - lpImgSectionHdr[nSectIndex].VirtualAddress*/);
														else
														{
															CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
															BOOL fbRestoreAttr(::GetConsoleScreenBufferInfo(hOut, &csbi));
															if (fbRestoreAttr)
																::SetConsoleTextAttribute(hOut, FOREGROUND_INTENSITY | COMMON_LVB_UNDERSCORE);

															ShowResourceStringArgs(hOut, IDS_MSG_SECT_FORMAT_VIRTUAL, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), nSectIndex + 1, &awcSectName[0], lpImgSectionHdr[nSectIndex].PointerToRawData, dwNextSectionVA, 
  																lpImgSectionHdr[nSectIndex].VirtualAddress, dwNextSectionA, lpImgSectionHdr[nSectIndex].Misc.VirtualSize);

															if (fbRestoreAttr)
																::SetConsoleTextAttribute(hOut, csbi.wAttributes);
														}
													}
													ShowString(hOut, szNewLine);

													//	Show Optional header pointers mapping
													ShowResourceString(hOut, IDS_MSG_OPT_HDR_PTRS_MAP, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
													ShowTargetSection(hOut, IDS_MSG_IMG_OPT_HDR_ENTRY_POINT, lpImgOptHdr ->AddressOfEntryPoint, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
													ShowTargetSection(hOut, IDS_MSG_IMG_OPT_HDR_CODE_BASE, lpImgOptHdr ->BaseOfCode, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
													ShowTargetSection(hOut, IDS_MSG_IMG_OPT_HDR_DATA_BASE, lpImgOptHdr ->BaseOfData, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
													ShowString(hOut, szNewLine);
													//	Show directories mappings
													ShowResourceString(hOut, IDS_MSG_DATA_DIRS_MAP, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
													for (DWORD ncIndex(0); ncIndex < lpImgOptHdr ->NumberOfRvaAndSizes; ++ncIndex)
													{
														if (lpImgDataDir[ncIndex].Size && lpImgDataDir[ncIndex].VirtualAddress)
														{
															switch(ncIndex)
															{
															case IMAGE_DIRECTORY_ENTRY_EXPORT:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_EXPORTS, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_IMPORT:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_IMPORTS, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_RESOURCE:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_RESOURCES, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_EXCEPTIONS, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_SECURITY:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_SECURITY, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_BASERELOC:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_RELOCATION_TABLE, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_DEBUG:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_DEBUG, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:																	
																ShowTargetSection(hOut, IDS_MSG_DATADIR_ARCHITECTURE, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_GLOBAL_PTR, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_TLS:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_TLS, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_LOAD_CFG, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_BOUND_IMPORT, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_IAT:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_IAT, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_DELAY_LOAD_IMPORT, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_DOTNET, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															case 15:
																ShowTargetSection(hOut, IDS_MSG_DATADIR_RESERVED, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															default:
																ShowResourceStringArgs(hOut, IDS_MSG_DATADIR_EXTRA, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), ncIndex);
																ShowTargetSection(hOut, 0, lpImgDataDir[ncIndex].VirtualAddress, lpImgSectionHdr, lpImgFileHdr ->NumberOfSections);
																break;
															}
														}
													}
													ShowString(hOut, szNewLine);

													if (g_wNumberOfSections < SECTIONS_TOTAL_MAX)
													{
														bool fbHeaderSpaceEnough(false);
														if (g_fbAdd || g_fbFileAdd)
														{
															// Here analyzed available space at PE headers region ...
															DWORD dwBaseAddress(reinterpret_cast<DWORD>(lpFileBase));
															DWORD dwFirstUnusedImgSectHdrDesc(reinterpret_cast<DWORD>(&lpImgSectionHdr[g_wNumberOfSections]));
															DWORD dwFirstUnusedImgSectHdrDescRVA(dwFirstUnusedImgSectHdrDesc - dwBaseAddress);
															DWORD dwHeadersEmptySpace(lpImgOptHdr ->SizeOfHeaders - dwFirstUnusedImgSectHdrDescRVA);

															if (sizeof(IMAGE_SECTION_HEADER) <= dwHeadersEmptySpace)
																fbHeaderSpaceEnough = true;
														}

														if ((g_fbAdd || g_fbFileAdd) && !fbHeaderSpaceEnough)
														{
															//	Number of sections is exceeded the limit of 96
															ShowResourceStringEx(hOut, IDS_ERROR_NO_EMPTY_SECTION_DESCRIPTOR, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
															ShowString(hOut, szNewLine);
															nRetCode = ERROR_NOT_ENOUGH_SPACE;		// There is not enough space within PE image headers to place another section's descriptor
														}
														else
														{
															// Check existing sections total ...
															if ((g_fbAdd && g_fbSectionNamePassed) || (g_fbFileAdd && g_fbFileSectionNamePassed))
															{
																if ((g_fbAdd && g_fbSectionNamePassed) && !IsSectionNameUnique(g_acNativeSectionName, lpImgSectionHdr, g_wNumberOfSections))
																{
																	ShowResourceStringArgsEx(hOut, IDS_ERROR_SECTION_EXISTS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0, &g_awcNativeSectionName[0]);
																	ShowString(hOut, szNewLine);
																	nRetCode = ERROR_SECTION_ALREADY_EXISTS;
																}

																if ((g_fbFileAdd && g_fbFileSectionNamePassed) && !IsSectionNameUnique(g_acNativeFileSectionName, lpImgSectionHdr, g_wNumberOfSections))
																{
																	ShowResourceStringArgsEx(hOut, IDS_ERROR_SECTION_EXISTS, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0, &g_awcFileNativeSectionName[0]);
																	ShowString(hOut, szNewLine);
																	nRetCode = ERROR_SECTION_ALREADY_EXISTS;
																}
															}

															if (!nRetCode)
															{
																// If add mode is on - do it
																if (g_fbAdd)															
																{
																	ShowResourceString(hOut, IDS_MSG_ADD_VIRTUAL_SECT_START, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
																	if (AddVirtualSection(lpFileBase, hOut, liFileSize) && fbReportEvent)
																		MakeReportEventRecord(g_wszIdent, STATUS_SEVERITY_SUCCESS, MSG_PROCESSING_SUCCESS, 1, &argv[1]);
																	ShowString(hOut, szNewLine);
																}

																// If file add mode - do it
																if (g_fbFileAdd)
																{
																	if (!FileExists(&g_wszFileName[0]))
																	{
																		ShowResourceStringArgs(hOut, IDS_ERROR_FILE_ISNT_FOUND, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_wszFileName[0]);
																		ShowString(hOut, szNewLine);
																	}
																	else
																	{
																		if (!CanAccessFile(&g_wszFileName[0], GENERIC_READ))
																		{
																			ShowResourceStringArgs(hOut, IDS_MSG_SECT_FILE_ACCESS_DENIED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_wszFileName[0]);
																			ShowString(hOut, szNewLine);
																		}
																		else
																		{
																			// Try to add data section
																			ShowResourceString(hOut, IDS_MSG_ADD_DATA_SECT_START, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
																			if (AddDataSection(hFile, lpFileBase, hOut) && fbReportEvent)
																				MakeReportEventRecord(g_wszIdent, STATUS_SEVERITY_SUCCESS, MSG_PROCESSING_SUCCESS, 1, &argv[1]);
																			if (lpFileBase)
																			{
																				::UnmapViewOfFile(lpFileBase);
																				lpFileBase = nullptr;
																			}
																			if (hFileMap)
																			{
																				::CloseHandle(hFileMap);
																				hFileMap = nullptr;
																			}
																			if (hFile)
																			{
																				::CloseHandle(hFile);
																				hFile = nullptr;
																			}
																			//	Adjust checksum
																			HANDLE hCheckFile(CreateFileW(argv[1], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0));
																			if (INVALID_HANDLE_VALUE != hCheckFile)
																			{
																				HANDLE hCheckFileMap(CreateFileMappingW(hCheckFile, nullptr, PAGE_READWRITE, 0, 0, nullptr));
																				if (hCheckFileMap == nullptr)
																				{
																					ShowSysErrorMsg(::GetLastError(), hOut);
																					::CloseHandle(hCheckFile);
																					ShowResourceStringEx(hOut, IDS_ERROR_CHECKSUM_RECALC_FAILED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
																					ShowString(hOut, szNewLine);
																					nRetCode = ERROR_CHECKSUM_RECALCULATING_FAILED;		// Recalc failed
																				}
																				else
																				{
																					LPVOID lpCheckFileBase(::MapViewOfFile(hCheckFileMap, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0));
																					if ( lpCheckFileBase == nullptr )
																					{
																						ShowSysErrorMsg(::GetLastError(), hOut);
																						::CloseHandle(hCheckFileMap);
																						::CloseHandle(hCheckFile);
																						ShowResourceStringEx(hOut, IDS_ERROR_CHECKSUM_RECALC_FAILED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
																						ShowString(hOut, szNewLine);
																						nRetCode = ERROR_CHECKSUM_RECALCULATING_FAILED;		// Recalc failed
																					}
																					else
																					{
																						LARGE_INTEGER li;
																						if (::GetFileSizeEx(hCheckFile, &li))
																						{
																							DWORD dwCheckSum1(MAXUINT), dwHeaderSum1(MAXUINT);
																							PIMAGE_NT_HEADERS lpImgNTHdrs(::CheckSumMappedFile(lpCheckFileBase, li.LowPart, &dwHeaderSum1, &dwCheckSum1));
																							if (lpImgNTHdrs != nullptr)
																								lpImgNTHdrs ->OptionalHeader.CheckSum = dwCheckSum1;
																							else
																							{
																								ShowSysErrorMsg(::GetLastError(), hOut);
																								ShowResourceStringEx(hOut, IDS_ERROR_CHECKSUM_RECALC_FAILED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
																								ShowString(hOut, szNewLine);
																								nRetCode = ERROR_CHECKSUM_RECALCULATING_FAILED;		// Recalc failed
																							}
																						}
																						else
																						{
																							ShowSysErrorMsg(::GetLastError(), hOut);
																							ShowResourceStringEx(hOut, IDS_ERROR_CHECKSUM_RECALC_FAILED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
																							ShowString(hOut, szNewLine);
																							nRetCode = ERROR_CHECKSUM_RECALCULATING_FAILED;		// Recalc failed
																						}
	
																						::UnmapViewOfFile(lpCheckFileBase);
																						::CloseHandle(hCheckFileMap);
																						::FlushFileBuffers(hCheckFile);
																						::CloseHandle(hCheckFile);
																					}
																				}
																			}
																			else
																			{
																				ShowSysErrorMsg(::GetLastError(), hOut);
																				ShowResourceStringEx(hOut, IDS_ERROR_CHECKSUM_RECALC_FAILED, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
																				ShowString(hOut, szNewLine);
																				nRetCode = ERROR_CHECKSUM_RECALCULATING_FAILED;		// Recalc failed
																			}
																		}
																	}
																}
															}
														}
													}
													else
													{
														//	Number of sections is exceeded the limit of 96
														ShowResourceStringArgsEx(hOut, IDS_ERROR_SECTIONS_TOO_MUCH, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0, g_wNumberOfSections);
														ShowString(hOut, szNewLine);
														nRetCode = ERROR_TOO_MUCH_SECTIONS;		// Too much sections
													}
												}
												else	
												{	
													ShowResourceStringEx(hOut, IDS_IMG_NOT_32BIT, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), FOREGROUND_RED | FOREGROUND_INTENSITY, 0);
													ShowString(hOut, szNewLine);
													nRetCode = ERROR_NOT_32_BIT_IMAGE;		// Not 32-bit image
												}
											}
										}
										if (lpFileBase)
											::UnmapViewOfFile(lpFileBase);
										if (hFileMap)
											::CloseHandle(hFileMap);
										if (hFile)
											::CloseHandle(hFile);
									}
								}
							}
						}
					}
				}
				else
				{
					ShowResourceStringArgs(hOut, IDS_ERROR_FILE_ISNT_FOUND, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), &g_wszFileName[0]);
					ShowString(hOut, szNewLine);
					nRetCode = ERROR_FILE_IS_NOT_FOUND;
				}
			}

			if (fbTitleChanged)
				::SetConsoleTitleW(szOldTitle);
		}
	}

	if (fbReportEvent)
		UnregEventSrc(g_wszIdent);

	//	Try to obtain console's processes list
	DWORD dwProcessListLen(CONSOLE_PROCESS_LIST_LAMBDA);
	LPDWORD lpdwList(nullptr);
	DWORD dwConAppTotal(0);
	if (AllocBuffer(dwProcessListLen, &lpdwList))
	{
		DWORD dwReturnValue(dwConAppTotal = ::GetConsoleProcessList(lpdwList, dwProcessListLen));
		if (dwReturnValue > dwProcessListLen)
		{
			//	Realloc buffer
			dwProcessListLen = ((dwReturnValue + (CONSOLE_PROCESS_LIST_LAMBDA - 1)) & ~(CONSOLE_PROCESS_LIST_LAMBDA - 1));
			if (AllocBuffer(dwProcessListLen, &lpdwList))
				dwConAppTotal = dwReturnValue = ::GetConsoleProcessList(lpdwList, dwProcessListLen);
		}

		DISPOSE_BUF(&lpdwList)
	}

	//	If console is attached to 2 or more processes - current process is running from cmd.exe/ps.exe etc.
	//	Else wait for user action - key press ...
	if (dwConAppTotal < 2)
	{
		ShowResourceString(hOut, IDS_EXIT_MESSAGE, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT));
		HANDLE hStdInput(::GetStdHandle(STD_INPUT_HANDLE));
		if (hStdInput)
		{
			::FlushConsoleInputBuffer(hStdInput);
			INPUT_RECORD ir = { 0 };
			do
			{
				DWORD dwEventsRead(0);
				if (!::ReadConsoleInputW(hStdInput, &ir, 1, &dwEventsRead))
					break;
			}
			while (ir.EventType != KEY_EVENT);
			::FlushConsoleInputBuffer(hStdInput);
		}
	}

	::SetUnhandledExceptionFilter(lpEFOriginal);
	return (nRetCode);
}
