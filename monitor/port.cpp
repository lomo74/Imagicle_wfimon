/*
WFIMON - Imagicle print2fax port monitor
Copyright (C) 2021 Lorenzo Monti

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 3
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "stdafx.h"
#include <versionhelpers.h>
#include "port.h"
#include "log.h"
#include "..\common\autoclean.h"
#include "..\common\defs.h"
#include "..\common\monutils.h"

//-------------------------------------------------------------------------------------
SYSTEMTIME CPort::m_DefSysTime = { 0 };

//-------------------------------------------------------------------------------------
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef NTSYSAPI NTSTATUS NTAPI RtlSetEnvironmentVariable_TYPE(
	IN OUT PVOID            *Environment OPTIONAL,
	IN PUNICODE_STRING      VariableName,
	IN PUNICODE_STRING      VariableValue
);

static RtlSetEnvironmentVariable_TYPE* RtlSetEnvironmentVariable = NULL;
static RtlSetEnvironmentVariable_TYPE* GetRtlSetEnvironmentVariable()
{
	if (RtlSetEnvironmentVariable)
	{
		return RtlSetEnvironmentVariable;
	}
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll)
	{
		return NULL;
	}
	RtlSetEnvironmentVariable = (RtlSetEnvironmentVariable_TYPE*)GetProcAddress(ntdll, "RtlSetEnvironmentVariable");
	return RtlSetEnvironmentVariable;
}

//-------------------------------------------------------------------------------------
static PVOID SetUserEnvironmentVariable(PVOID Environment, LPCWSTR varName, LPCWSTR varVal) {
	UNICODE_STRING a = { 0 };
	UNICODE_STRING b = { 0 };
	a.Buffer = const_cast<LPWSTR>(varName);
	a.Length = (USHORT)wcslen(varName) * sizeof(WCHAR);
	a.MaximumLength = a.Length;
	b.Buffer = const_cast<LPWSTR>(varVal);
	b.Length = (USHORT)wcslen(varVal) * sizeof(WCHAR);
	b.MaximumLength = b.Length;
	PVOID env = Environment;
	if (GetRtlSetEnvironmentVariable()) {
		RtlSetEnvironmentVariable(&env, &a, &b);
	} else {
		g_pLog->Error(L"SetUserEnvironmentVariable: could not get address of ntdll.RtlSetEnvironmentVariable, can't set %s=%s", varName, varVal);
	}
	return env;
}

//-------------------------------------------------------------------------------------
static DWORD FindUserSessionId(LPCWSTR szUser, DWORD* pdwSessionId)
{
	PWTS_SESSION_INFOW pSessInfo;
	DWORD dwCount, dwBytes, dwErr = 0;
	LPWSTR lpSessUser;
	BOOL bFound = FALSE;

	_ASSERT(pdwSessionId);

	if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessInfo, &dwCount))
	{
		for (DWORD i = 0; i < dwCount; i++)
		{
			if (pSessInfo[i].State == WTSActive)
			{
				if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, pSessInfo[i].SessionId,
					WTSUserName, &lpSessUser, &dwBytes))
				{
					if (_wcsicmp(lpSessUser, szUser) == 0)
						bFound = TRUE;

					WTSFreeMemory(lpSessUser);

					if (bFound)
					{
						*pdwSessionId = pSessInfo[i].SessionId;
						g_pLog->Info(L"FindUserSessionId: found user session with id=%li", *pdwSessionId);
						break;
					}
				}
				else
				{
					dwErr = GetLastError();
					g_pLog->Error(L"FindUserSessionId: WTSQuerySessionInformationW failed: 0x%0.8X", dwErr);
					break;
				}
			}
		}

		WTSFreeMemory(pSessInfo);
	}
	else
	{
		dwErr = GetLastError();
		g_pLog->Error(L"FindUserSessionId: WTSEnumerateSessionsW failed: 0x%0.8X", dwErr);
	}

	return (bFound
		? ERROR_SUCCESS
		: (dwErr
			? dwErr
			: 0xFFFFFFFF));
}

//-------------------------------------------------------------------------------------
static BOOL GetExplorerToken(DWORD dwSessionId, HANDLE* phToken)
{
	DWORD winlogonSessId, explorerPid = 0;
	PROCESSENTRY32W procEntry = { 0 };
	BOOL bRet = FALSE;
	HANDLE hProcess, hPToken, hPTokenDup;

	_ASSERT(phToken);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		procEntry.dwSize = sizeof(PROCESSENTRY32W);

		if (Process32FirstW(hSnap, &procEntry))
		{
			do
			{
				if (_wcsicmp(procEntry.szExeFile, L"explorer.exe") == 0)
				{
					if (ProcessIdToSessionId(procEntry.th32ProcessID, &winlogonSessId)
						&& winlogonSessId == dwSessionId)
					{
						//found explorer.exe running into this session
						explorerPid = procEntry.th32ProcessID;
						break;
					}
				}
			} while (Process32Next(hSnap, &procEntry));

			if (explorerPid)
			{
				if ((hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, explorerPid)) != NULL)
				{
					if (OpenProcessToken(hProcess,
						TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE,
						&hPToken))
					{
						if (DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL,
							SecurityIdentification, TokenPrimary, &hPTokenDup))
						{
							LPVOID lpData = reinterpret_cast<LPVOID>(dwSessionId);
							if (SetTokenInformation(hPTokenDup, TokenSessionId, lpData, sizeof(DWORD)))
							{
								*phToken = hPTokenDup;
								bRet = TRUE;
							}
							else
								g_pLog->Critical(L"GetExplorerToken: SetTokenInformation failed: 0x%0.8X", GetLastError());
						}
						else
							g_pLog->Critical(L"GetExplorerToken: DuplicateTokenEx failed: 0x%0.8X", GetLastError());

						CloseHandle(hPToken);
					}

					CloseHandle(hProcess);
				}
				else
					g_pLog->Critical(L"GetExplorerToken: OpenProcessToken failed: 0x%0.8X", GetLastError());
			}
			else
				g_pLog->Critical(L"GetExplorerToken: Unable to find a suitable explorer.exe process");
		}
		else
			g_pLog->Critical(L"GetExplorerToken: Process32FirstW failed: 0x%0.8X", GetLastError());

		CloseHandle(hSnap);
	}
	else
		g_pLog->Critical(L"GetExplorerToken: CreateToolhelp32Snapshot failed: 0x%0.8X", GetLastError());
	
	return bRet;
}

//-------------------------------------------------------------------------------------
static BOOL WriteToPipe(HANDLE hPipe, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
						DWORD dwMilliseconds, LPOVERLAPPED pOv)
{
	DWORD cbWritten = 0, dwLe = 0;
	BOOL bWaitingWrite = FALSE;

	if (!WriteFile(hPipe, lpBuffer, nNumberOfBytesToWrite, NULL, pOv))
	{
		if ((dwLe = GetLastError()) != ERROR_IO_PENDING)
		{
			g_pLog->Critical(L"WriteToPipe: WriteFile failed: 0x%0.8X", dwLe);
			return FALSE;
		}

		bWaitingWrite = TRUE;
	}

	//se l'operazione è in stato di ERROR_IO_PENDING...
	if (bWaitingWrite)
	{
		//restiamo in attesa di un evento
		switch (WaitForSingleObject(pOv->hEvent, dwMilliseconds))
		{
		case WAIT_OBJECT_0:		// operazione completata
			break;
		case WAIT_TIMEOUT:		// timeout
			g_pLog->Critical(L"WriteToPipe: WaitForSingleObject timeout");
			return FALSE;
			break;
		default:				// non dovremmo mai arrivare qui
			return FALSE;
			break;
		}
	}

	//controlliamo l'esito dell'operazione asincrona
	if (!GetOverlappedResult(hPipe, pOv, &cbWritten, FALSE))
	{
		g_pLog->Critical(L"WriteToPipe: GetOverlappedResult failed: 0x%0.8X", GetLastError());
		return FALSE;
	}

	BOOL bRet = (cbWritten == nNumberOfBytesToWrite);

	if (!bRet)
	{
		g_pLog->Error(L"WriteToPipe: wrong number of bytes written to file (cbWritten=%li nNumberOfBytesToWrite=%li)", cbWritten, nNumberOfBytesToWrite);
	}

	return bRet;
}

//-------------------------------------------------------------------------------------
typedef BOOL (WINAPI *PFNWTSQUERYUSERTOKEN)(ULONG, PHANDLE);

static PFNWTSQUERYUSERTOKEN fnWTSQueryUserToken = NULL;

static PFNWTSQUERYUSERTOKEN GetWTSQueryUserToken()
{
	if (fnWTSQueryUserToken)
		return fnWTSQueryUserToken;

	HMODULE hMod = GetModuleHandleW(L"wtsapi32.dll");

	if (!hMod)
		hMod = LoadLibraryW(L"wtsapi32.dll");

	if (!hMod)
	{
		g_pLog->Critical(L"GetWTSQueryUserToken: LoadLibraryW failed: 0x%0.8X", GetLastError());
		return NULL;
	}

	fnWTSQueryUserToken = (PFNWTSQUERYUSERTOKEN)GetProcAddress(hMod, "WTSQueryUserToken");

	return fnWTSQueryUserToken;
}

//-------------------------------------------------------------------------------------
static bool isAbsPath(LPCWSTR szPath) {
	if (szPath[0] == L'\\')
		return true;
	if (szPath[0] == L'/')
		return true;
	if (((szPath[0] >= L'A' && szPath[0] <= L'Z') ||
		(szPath[0] >= L'a' && szPath[0] <= L'z')) &&
		szPath[1] == L':')
		return true;
	return false;
}
 
//-------------------------------------------------------------------------------------
void CPort::StartExe(LPCWSTR szExeName, LPCWSTR szWorkingDir, LPWSTR szCmdLine,
					 BOOL bTSEnabled, DWORD dwSessionId)
{

	LPWSTR szCommand;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD dwFlags = 0;
	HANDLE htok = NULL, huser = NULL;
	BOOL bIsXp, bRet;
	LPVOID lpEnv = NULL;
	BOOL bTokOk = FALSE;

	bIsXp = IsWindowsXPOrGreater();

	if (bIsXp)
	{
		g_pLog->Debug(L"CPort::StartExe: running on Windows XP or higher");

		if (!GetWTSQueryUserToken())
		{
			g_pLog->Critical(L"CPort::StartExe: unable to get WTSQueryUserToken function");
			return;
		}

		OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, TRUE, &huser);
		RevertToSelf();
	}

	if (bTSEnabled)
	{
		//Terminal Server present
		if (bIsXp)
		{
			g_pLog->Debug(L"CPort::StartExe: using WTSQueryUserToken to get user token");

			//we have WTSQueryUserToken
			if ((bTokOk = fnWTSQueryUserToken(dwSessionId, &htok)) == FALSE)
				g_pLog->Critical(L"CPort::StartExe: fnWTSQueryUserToken failed: 0x%0.8X", GetLastError());
		}
		else
		{
			g_pLog->Debug(L"CPort::StartExe: using GetExplorerToken to get user token");

			//we DON'T have WTSQueryUserToken; look for a running
			//explorer.exe into this session, and grab token from it
			bTokOk = GetExplorerToken(dwSessionId, &htok);
		}
	}
	else
	{
		//Windows 2000 Pro or Windows 2000 Server w/o TS
		bTokOk = TRUE;
	}

	if (bTokOk)
	{
		szCommand = new WCHAR[MAX_COMMAND];

		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(si);
		si.lpDesktop = L"winsta0\\default";
		si.dwFlags |= STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_SHOWNORMAL;

		//componiamo il comando eseguibile...
		if (!isAbsPath(szExeName) && szWorkingDir)
		{
			//Not a full path, prefix with szWorkingDir
			swprintf_s(szCommand, MAX_COMMAND, L"\"%s", szWorkingDir);
			size_t pos = wcslen(szCommand);
			if (pos == 0 || szCommand[pos - 1] != L'\\')
				wcscat_s(szCommand, MAX_COMMAND, L"\\");
		}
		else
		{
			//Full path
			swprintf_s(szCommand, MAX_COMMAND, L"\"");
		}

		wcscat_s(szCommand, MAX_COMMAND, szExeName);
		wcscat_s(szCommand, MAX_COMMAND, L"\" ");
		wcscat_s(szCommand, MAX_COMMAND, szCmdLine);

		//creazione environment
		if (CreateEnvironmentBlock(&lpEnv, htok, FALSE))
			dwFlags |= CREATE_UNICODE_ENVIRONMENT;
		else
			g_pLog->Error(L"CPort::StartExe: CreateEnvironmentBlock failed: 0x%0.8X", GetLastError());

		WCHAR jobid[10];
		WCHAR totalpages[10];
		WCHAR priority[10];
		WCHAR submitted[20];
		_itow_s(m_nJobId, jobid, LENGTHOF(jobid), 10);
		_itow_s(TotalPages(), totalpages, LENGTHOF(totalpages), 10);
		_itow_s(Priority(), priority, LENGTHOF(priority), 10);
		SYSTEMTIME& st = Submitted();
		swprintf_s(submitted, LENGTHOF(submitted), L"%04u%02u%02u%02u%02u%02u%03u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_computername", ComputerName());
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_username", UserName());
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_filename", FileName());
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_printername", m_szPrinterName);
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_portname", PortName());
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_jobid", jobid);
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_jobtitle", JobTitle());
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_totalpages", totalpages);
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_priority", priority);
		lpEnv = SetUserEnvironmentVariable(lpEnv, L"WFI_submitted", submitted);

		g_pLog->Debug(L"CPort::StartExe: invoking %s in session %d for %s", (bIsXp ? L"CreateProcessAsUserW" : L"CreateProcessW"), dwSessionId, UserName());
		g_pLog->Debug(L"CPort::StartExe: command is %s", szCommand);

		//esecuzione
		if (htok)
			bRet = CreateProcessAsUserW(htok, NULL, szCommand, NULL, NULL, FALSE, dwFlags, lpEnv, szWorkingDir, &si, &pi);
		else
			bRet = CreateProcessW(NULL, szCommand, NULL, NULL, FALSE, dwFlags, lpEnv, szWorkingDir, &si, &pi);

		if (bRet)
		{
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
		else
			g_pLog->Critical(L"CPort::StartExe: %s failed: 0x%0.8X", (htok ? L"CreateProcessAsUserW" : L"CreateProcessW"), GetLastError());

		//distruzione environment
		if (lpEnv)
			DestroyEnvironmentBlock(lpEnv);

		delete[] szCommand;

		if (htok)
			CloseHandle(htok);
	}

	if (huser)
	{
		if (!SetThreadToken(NULL, huser))
			g_pLog->Error(L"CPort::StartExe: SetThreadToken failed: 0x%0.8X", GetLastError());
		CloseHandle(huser);
	}
}

//-------------------------------------------------------------------------------------
CPort::CPort()
{
	Initialize();
}

//-------------------------------------------------------------------------------------
CPort::CPort(LPCWSTR szPortName)
{
	Initialize(szPortName);
}

//-------------------------------------------------------------------------------------
void CPort::Initialize()
{
	*m_szPortName = L'\0';
	*m_szOutputPath = L'\0';
	m_szPrinterName = NULL;
	m_cchPrinterName = 0;
	m_pPattern = NULL;
	*m_szExecPath = L'\0';
	wcscpy_s(m_szGUIPath, LENGTHOF(m_szGUIPath), L"wfigui.exe");
	*m_szFileName = L'\0';
	m_hFile = INVALID_HANDLE_VALUE;
	m_nJobId = 0;
	m_pJobInfo2 = NULL;
	m_cbJobInfo2 = 0;
	m_hToken = NULL;
	m_bRestrictedToken = FALSE;
	m_bLogonInvalidated = TRUE;
	SetFilePatternString(L"fax%i.ps");
}

//-------------------------------------------------------------------------------------
void CPort::Initialize(LPCWSTR szPortName)
{
	Initialize();
	wcscpy_s(m_szPortName, LENGTHOF(m_szPortName), szPortName);
}

//-------------------------------------------------------------------------------------
CPort::~CPort()
{
	if (m_pPattern)
		delete m_pPattern;

	if (m_szPrinterName)
		delete[] m_szPrinterName;

	if (m_pJobInfo2)
		delete[] m_pJobInfo2;
}

//-------------------------------------------------------------------------------------
void CPort::SetFilePatternString(LPCWSTR szPattern)
{
	if (m_pPattern)
		delete m_pPattern;

	m_pPattern = new CPattern(szPattern, this, FALSE);
}

//-------------------------------------------------------------------------------------
LPCWSTR CPort::FilePattern() const
{
	if (m_pPattern)
		return m_pPattern->PatternString();
	else
		return CPattern::szDefaultFilePattern;
}

//-------------------------------------------------------------------------------------
BOOL CPort::GetJobInfo()
{
	//retrieve job info
	DWORD cbNeeded;

	CPrinterHandle printer(m_szPrinterName);

	if (!printer.Handle())
	{
		g_pLog->Critical(L"CPort::GetJobInfo: OpenPrinterW failed: 0x%0.8X", GetLastError());
		return FALSE;
	}

	//JOB_INFO_2
	GetJobW(printer, m_nJobId, 2, NULL, 0, &cbNeeded);

	if (!m_pJobInfo2 || m_cbJobInfo2 < cbNeeded)
	{
		if (m_pJobInfo2)
			delete[] m_pJobInfo2;

		m_cbJobInfo2 = cbNeeded;
		m_pJobInfo2 = (JOB_INFO_2W*)new BYTE[cbNeeded];
	}

	if (!GetJobW(printer, m_nJobId, 2, (LPBYTE)m_pJobInfo2, m_cbJobInfo2, &cbNeeded))
	{
		g_pLog->Critical(L"CPort::GetJobInfo: GetJobW failed: 0x%0.8X", GetLastError());
		return FALSE;
	}

	return TRUE;
}

//-------------------------------------------------------------------------------------
BOOL CPort::StartJob(DWORD nJobId, LPWSTR szJobTitle, LPWSTR szPrinterName)
{
	UNREFERENCED_PARAMETER(szJobTitle);

	_ASSERTE(m_pPattern != NULL);

	if (!m_pPattern)
	{
		g_pLog->Critical(L"CPort::StartJob: m_pPattern is NULL");
		return FALSE;
	}

	m_nJobId = nJobId;

	m_pPattern->Reset();

	//retrieve job info
	if (!GetJobInfo())
	{
		g_pLog->Critical(L"CPort::StartJob: cannot read print job information");
		return FALSE;
	}

	//determine if a job was submitted locally by comparing local netbios name
	//with that stored into m_pJobInfo
	WCHAR szComputerName[256];
	DWORD nSize = LENGTHOF(szComputerName);

	GetComputerNameW(szComputerName, &nSize);

	//copy printer name locally
	size_t len = wcslen(szPrinterName) + 1;

	if (!m_szPrinterName || m_cchPrinterName < len)
	{
		if (m_szPrinterName)
			delete[] m_szPrinterName;

		m_cchPrinterName = (DWORD)len;
		m_szPrinterName = new WCHAR[len];
	}

	wcscpy_s(m_szPrinterName, m_cchPrinterName, szPrinterName);

	return TRUE;
}

//-------------------------------------------------------------------------------------
DWORD CPort::CreateOutputFile()
{
	_ASSERTE(m_pPattern != NULL);

	if (!m_pPattern)
	{
		g_pLog->Critical(L"CPort::CreateOutputFile: m_pPattern is NULL");
		return ERROR_CAN_NOT_COMPLETE;
	}

	HKEY hkRoot;
	DWORD cbData;

	DWORD rc;

	//apre chiave di registro
	rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Imagicle print2fax", 0,
		STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hkRoot);

	if (rc != ERROR_SUCCESS)
	{
		g_pLog->Critical(L"CPort::CreateOutputFile: RegOpenKeyExW failed: 0x%0.8X", rc);
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	//legge InstallDir
	cbData = sizeof(m_szExecPath);
	if ((rc = RegQueryValueExW(hkRoot, L"WorkingDir", NULL, NULL, (LPBYTE)m_szExecPath, &cbData)) == ERROR_SUCCESS)
	{
		DWORD len = cbData / sizeof(WCHAR);
		if (len >= LENGTHOF(m_szExecPath))
			len = LENGTHOF(m_szExecPath) - 1;
		m_szExecPath[len] = L'\0';
	}
	else
	{
		g_pLog->Error(L"CPort::CreateOutputFile: RegQueryValueExW(WorkingDir) failed: 0x%0.8X", rc);
		*m_szExecPath = L'\0';
	}

	g_pLog->Debug(L"CPort::CreateOutputFile: m_szExecPath is \"%s\"", m_szExecPath);

	//legge GUIPath
	cbData = sizeof(m_szGUIPath);
	if ((rc = RegQueryValueExW(hkRoot, L"GUIPath", NULL, NULL, (LPBYTE)m_szGUIPath, &cbData)) == ERROR_SUCCESS)
	{
		DWORD len = cbData / sizeof(WCHAR);
		if (len >= LENGTHOF(m_szGUIPath))
			len = LENGTHOF(m_szGUIPath) - 1;
		m_szGUIPath[len] = L'\0';
	}
	else
	{
		g_pLog->Warn(L"CPort::CreateOutputFile: RegQueryValueExW(GUIPath) failed: 0x%0.8X", rc);
		wcscpy_s(m_szGUIPath, LENGTHOF(m_szGUIPath), L"wfigui.exe");
	}

	g_pLog->Debug(L"CPort::CreateOutputFile: m_szGUIPath is \"%s\"", m_szGUIPath);

	//chiude registro
	RegCloseKey(hkRoot);

	if (SHGetSpecialFolderPathW(NULL, m_szOutputPath, CSIDL_COMMON_APPDATA, FALSE))
	{
		wcscat_s(m_szOutputPath, LENGTHOF(m_szOutputPath), L"\\Imagicle print2fax\\faxtmp");
	}
	else
	{
		g_pLog->Critical(L"CPort::CreateOutputFile: SHGetSpecialFolderPathW failed: 0x%0.8X", GetLastError());
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	/*start composing the output filename*/
	wcscpy_s(m_szFileName, LENGTHOF(m_szFileName), m_szOutputPath);

	/*append a backslash*/
	size_t pos = wcslen(m_szFileName);
	if (pos == 0 || m_szFileName[pos - 1] != L'\\')
	{
		wcscat_s(m_szFileName, LENGTHOF(m_szFileName), L"\\");
		pos++;
	}

	/*the search algorithm uses search strings from "search fields", if any*/
	WCHAR szSearchPath[MAX_PATH + 1];
	wcscpy_s(szSearchPath, LENGTHOF(szSearchPath), m_szFileName);

	/*start finding a file name*/
	do
	{
		m_szFileName[pos] = L'\0';
		szSearchPath[pos] = L'\0';

		/*get current value from pattern*/
		LPWSTR szFileName = m_pPattern->Value();
		LPWSTR szSearchName = m_pPattern->SearchValue();

		/*append it to output file name*/
		wcscat_s(m_szFileName, LENGTHOF(m_szFileName), szFileName);
		wcscat_s(szSearchPath, LENGTHOF(szSearchPath), szSearchName);

		/*check if parent directory exists*/
		GetFileParent(m_szFileName, m_szParent, LENGTHOF(m_szParent));
		if (RecursiveCreateFolder(m_szParent) != ERROR_SUCCESS)
		{
			g_pLog->Critical(L"CPort::CreateOutputFile: can't create output directory: 0x%0.8X", GetLastError());
			return ERROR_DIRECTORY;
		}

		//is this file name usable?
		if (FilePatternExists(szSearchPath))
		{
			g_pLog->Debug(L"CPort::CreateOutputFile: file %s exists, moving on", szSearchPath);
			continue;
		}

		//output on a regular file
		m_hFile = CreateFileW(m_szFileName, GENERIC_WRITE, 0,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (m_hFile == INVALID_HANDLE_VALUE)
		{
			g_pLog->Critical(L"CPort::CreateOutputFile: CreateFileW failed: 0x%0.8X", GetLastError());
			return ERROR_FILE_INVALID;
		}
		else
			return ERROR_SUCCESS;
	} while (m_pPattern->NextValue()); //loop until there are no more combinations for pattern

	g_pLog->Critical(L"CPort::CreateOutputFile: can't get a valid filename");

	return ERROR_FILE_EXISTS;
}

//-------------------------------------------------------------------------------------
BOOL CPort::WriteToFile(LPCVOID lpBuffer, DWORD cbBuffer, LPDWORD pcbWritten)
{
	BOOL bRet = WriteFile(m_hFile, lpBuffer, cbBuffer, pcbWritten, NULL);

	if (!bRet)
	{
		g_pLog->Critical(L"CPort::WriteToFile: WriteFile failed: 0x%0.8X", GetLastError());
	}

	return bRet;
}

//-------------------------------------------------------------------------------------
BOOL CPort::EndJob()
{
	_ASSERTE(m_pPattern != NULL);

	if (!m_pPattern)
	{
		g_pLog->Critical(L"CPort::EndJob: m_pPattern is NULL");
		return FALSE;
	}

	//read job info again (to get total # of pages)
	if (!GetJobInfo())
	{
		g_pLog->Critical(L"CPort::EndJob: cannot read print job information");
		return FALSE;
	}

	//done with the file, close it and flush buffers
	FlushFileBuffers(m_hFile);
	CloseHandle(m_hFile);
	m_hFile = INVALID_HANDLE_VALUE;

	//tell the spooler we are done with the job
	CPrinterHandle printer(m_szPrinterName);

	if (printer.Handle())
		SetJobW(printer, JobId(), 0, NULL, JOB_CONTROL_DELETE);

	//eseguiamo le operazioni post-spooling
	//modalità multi-documento
	static LPCWSTR szPipeTemplate = L"\\\\.\\pipe\\wfi_sessid%0.8X";
	WCHAR szPipeName[32];
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	BOOL bTSEnabled = FALSE;
	DWORD dwSessionId = 0, dwRet;

	dwRet = FindUserSessionId(UserName(), &dwSessionId);

	if (dwRet == ERROR_SUCCESS)
	{
		g_pLog->Debug(L"CPort::EndJob: running on terminal server enabled system");
		bTSEnabled = TRUE;
	}
	else if (dwRet != ERROR_APP_WRONG_OS)
	{
		if (IsWindowsXPOrGreater())
		{
			g_pLog->Debug(L"CPort::EndJob: trying WTSGetActiveConsoleSessionId to get user session id");

			typedef DWORD (WINAPI *PFNWTSGETACTIVECONSOLESESSIONID)(void);
			PFNWTSGETACTIVECONSOLESESSIONID fnWTSGetActiveConsoleSessionId;

			HMODULE hMod = GetModuleHandleW(L"kernel32.dll");

			if (!hMod)
			{
				g_pLog->Critical(L"CPort::EndJob: GetModuleHandleW failed: 0x%0.8X", GetLastError());
				return FALSE;
			}

			fnWTSGetActiveConsoleSessionId = (PFNWTSGETACTIVECONSOLESESSIONID)GetProcAddress(hMod, "WTSGetActiveConsoleSessionId");

			if (!fnWTSGetActiveConsoleSessionId)
			{
				g_pLog->Critical(L"CPort::EndJob: GetProcAddress failed: 0x%0.8X", GetLastError());
				return FALSE;
			}

			if ((dwSessionId = fnWTSGetActiveConsoleSessionId()) == 0xFFFFFFFF)
			{
				g_pLog->Critical(L"CPort::EndJob: WTSGetActiveConsoleSessionId failed: 0x%0.8X", GetLastError());
				return FALSE;
			}

			g_pLog->Debug(L"CPort::EndJob: running on terminal server");
			bTSEnabled = TRUE;
		}
		else
		{
			g_pLog->Critical(L"CPort::EndJob: FindUserSessionId returned an unexpected error: 0x%0.8X", dwRet);
			return FALSE;
		}
	}

	swprintf_s(szPipeName, LENGTHOF(szPipeName), szPipeTemplate, dwSessionId);

	//cerchiamo la pipe...
	hPipe = CreateFileW(
		szPipeName,
		GENERIC_WRITE | FILE_FLAG_OVERLAPPED,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	LPWSTR szTitle = JobTitle();

	if (hPipe != INVALID_HANDLE_VALUE)
	{
		g_pLog->Debug(L"CPort::EndJob: pipe %s found, communicating with the GUI", szPipeName);

		//pipe trovata
		DWORD len;
		OVERLAPPED ov;

		ZeroMemory(&ov, sizeof(ov));
		ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

		if (ov.hEvent == NULL)
		{
			g_pLog->Debug(L"CPort::EndJob: CreateEvent failed: 0x%0.8X", GetLastError());
			return FALSE;
		}

		DWORD nPages = TotalPages();
		WriteToPipe(hPipe, &nPages, sizeof(nPages), 1000, &ov);

		//file name
		len = (DWORD)wcslen(m_szFileName);
		WriteToPipe(hPipe, &len, sizeof(len), 1000, &ov);
		WriteToPipe(hPipe, m_szFileName, len * sizeof(WCHAR), 1000, &ov);

		//title
		len = (DWORD)wcslen(szTitle);
		WriteToPipe(hPipe, &len, sizeof(len), 1000, &ov);
		WriteToPipe(hPipe, szTitle, len * sizeof(WCHAR), 1000, &ov);

		CloseHandle(hPipe);
		CloseHandle(ov.hEvent);
	}
	else
	{
		g_pLog->Debug(L"CPort::EndJob: pipe %s NOT found, starting the GUI", szPipeName);

		//pipe non trovata, lancio l'exe
		DWORD len1, len2, x;
		LPWSTR szCmdLine = NULL, szHexTitle = NULL;

		len1 = (DWORD)wcslen(szTitle);
		len2 = (DWORD)wcslen(m_szFileName) + (len1 * 4) + 200;

		szHexTitle = new WCHAR[len1 * 4 + 1];
		szCmdLine = new WCHAR[len2 + 1];

		for (x = 0; x < len1; x++)
		{
			union
			{
				WCHAR c;
				BYTE b[2];
			} u = { szTitle[x] };

			BYTE b1, b2;

			b1 = (u.b[0] & 0xF0) >> 4;
			b2 = (u.b[0] & 0x0F);

			if (b1 <= 9)
				szHexTitle[x * 4 + 0] = L'0' + b1;
			else
				szHexTitle[x * 4 + 0] = L'A' + b1 - 10;

			if (b2 <= 9)
				szHexTitle[x * 4 + 1] = L'0' + b2;
			else
				szHexTitle[x * 4 + 1] = L'A' + b2 - 10;

			b1 = (u.b[1] & 0xF0) >> 4;
			b2 = (u.b[1] & 0x0F);

			if (b1 <= 9)
				szHexTitle[x * 4 + 2] = L'0' + b1;
			else
				szHexTitle[x * 4 + 2] = L'A' + b1 - 10;

			if (b2 <= 9)
				szHexTitle[x * 4 + 3] = L'0' + b2;
			else
				szHexTitle[x * 4 + 3] = L'A' + b2 - 10;
		}

		szHexTitle[x * 4] = L'\0';

		//componiamo la linea di comando
		//2013-12-02 inviamo anche lo switch -fromspooler per distinguere i job inviati dallo spooler
		//da quelli aggiunti manualmente o da riga di comando
		swprintf_s(szCmdLine, (size_t)len2 + 1, L"-fromspooler -pages %lu -title \"%s\" \"%s\"", TotalPages(), szHexTitle, m_szFileName);

		g_pLog->Debug(L"CPort::EndJob: GUI executable is %s", GUIPath());
		g_pLog->Debug(L"CPort::EndJob: GUI exec path is %s", ExecPath());
		g_pLog->Debug(L"CPort::EndJob: GUI command line is %s", szCmdLine);

		//esecuzione
		StartExe(GUIPath(), ExecPath(), szCmdLine, bTSEnabled, dwSessionId);

		delete[] szCmdLine;
		delete[] szHexTitle;
	}

	*m_szFileName = L'\0';

	return TRUE;
}

//-------------------------------------------------------------------------------------
void CPort::SetConfig(LPPORTCONFIG pConfig)
{
	g_pLog->SetLogLevel(pConfig->nLogLevel);
	wcscpy_s(m_szPortName, LENGTHOF(m_szPortName), pConfig->szPortName);
}

//-------------------------------------------------------------------------------------
LPCWSTR CPort::ComputerName() const
{
	if (m_pJobInfo2)
	{
		//strip backslashes off
		LPWSTR pBuf = m_pJobInfo2->pMachineName;

		while (*pBuf == L'\\')
			pBuf++;

		return pBuf;
	}
	else
		return L"";
}

//-------------------------------------------------------------------------------------
LPWSTR CPort::Bin() const
{
	static WCHAR szBinName[16];

	if (!m_pJobInfo2 || !m_pJobInfo2->pDevMode || (m_pJobInfo2->pDevMode->dmFields & DM_DEFAULTSOURCE) == 0)
		return L"";

	switch (m_pJobInfo2->pDevMode->dmDefaultSource)
	{
	case DMBIN_AUTO:
		return L"AUTO";
	case DMBIN_CASSETTE:
		return L"CASSETTE";
	case DMBIN_ENVELOPE:
		return L"ENVELOPE";
	case DMBIN_ENVMANUAL:
		return L"ENVMANUAL";
	//case DMBIN_FIRST:
	//	return L"FIRST";
	case DMBIN_FORMSOURCE:
		return L"FORMSOURCE";
	case DMBIN_LARGECAPACITY:
		return L"LARGECAPACITY";
	case DMBIN_LARGEFMT:
		return L"LARGEFMT";
	//case DMBIN_LAST:
	//	return L"LAST";
	case DMBIN_LOWER:
		return L"LOWER";
	case DMBIN_MANUAL:
		return L"MANUAL";
	case DMBIN_MIDDLE:
		return L"MIDDLE";
	//case DMBIN_ONLYONE:
	//	return L"ONLYONE";
	case DMBIN_TRACTOR:
		return L"TRACTOR";
	case DMBIN_SMALLFMT:
		return L"SMALLFMT";
	case DMBIN_UPPER:
		return L"UPPER";
	default:
		if (m_pJobInfo2->pDevMode->dmDefaultSource >= DMBIN_USER)
		{
			swprintf_s(szBinName, LENGTHOF(szBinName), L"USER%hi", m_pJobInfo2->pDevMode->dmDefaultSource);
		}
		else
		{
			swprintf_s(szBinName, LENGTHOF(szBinName), L"%hi", m_pJobInfo2->pDevMode->dmDefaultSource);
		}
		return szBinName;
	}
}

//-------------------------------------------------------------------------------------
DWORD CPort::RecursiveCreateFolder(LPCWSTR szPath)
{
	WCHAR szPathBuf[MAX_PATH + 1];
	WCHAR szParent[MAX_PATH + 1];
	LPCWSTR pPath = szPath;
	size_t len;

	/*strip off leading backslashes*/
	len = wcslen(szPath);
	if (len > 0 && ISSLASH(szPath[len - 1]))
	{
		/*make a copy of szPath only if needed*/
		wcscpy_s(szPathBuf, LENGTHOF(szPathBuf), szPath);
		pPath = szPathBuf;
		while (len > 0 && ISSLASH(szPathBuf[len - 1]))
		{
			szPathBuf[len - 1] = L'\0';
			len--;
		}
	}
	/*only drive letter left or the directory already exists*/
	if (len < 3 || DirectoryExists(pPath))
		return ERROR_SUCCESS;
	else
	{
		GetFileParent(pPath, szParent, LENGTHOF(szParent));
		if (wcscmp(pPath, szParent) == 0)
			return ERROR_SUCCESS;
		/*our parent must exist before we can get created*/
		DWORD dwRet = RecursiveCreateFolder(szParent);
		if (dwRet != ERROR_SUCCESS)
			return dwRet;
		if (!CreateDirectoryW(pPath, NULL))
			return GetLastError();
		return ERROR_SUCCESS;
	}
}
