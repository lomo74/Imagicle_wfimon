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
#include "log.h"
#include <string.h>
#include <stdarg.h>
//---------------------------------------------------------------------------

static const unsigned short int BOM = 0xFEFF;

CWfiLog* g_pLog = NULL;
//---------------------------------------------------------------------------

#define CHECK_LEVEL(lev) do { if (m_hLogFile == INVALID_HANDLE_VALUE || m_nLogLevel < lev) return; } while (0)
//---------------------------------------------------------------------------

CWfiLog::CWfiLog()
: m_nLogLevel(LOGLEVEL_ERRORS), m_bFlushNeeded(FALSE)
{
	m_szBuffer[0] = L'\0';

	m_hStop = CreateEvent(NULL, FALSE, FALSE, NULL);
	m_hThread = CreateThread(NULL, 0, FlushThread, this, CREATE_SUSPENDED, NULL);

	CreateLogFile();

	InitializeCriticalSection(&m_CSLog);

	ResumeThread(m_hThread);
}
//---------------------------------------------------------------------------

CWfiLog::~CWfiLog()
{
	SetEvent(m_hStop);
	WaitForSingleObject(m_hThread, INFINITE);
	CloseHandle(m_hThread);
	CloseHandle(m_hStop);

	if (m_hLogFile != INVALID_HANDLE_VALUE)
		CloseHandle(m_hLogFile);

	DeleteCriticalSection(&m_CSLog);
}
//---------------------------------------------------------------------------

DWORD WINAPI CWfiLog::FlushThread(LPVOID pParam)
{
	CWfiLog* pLog = static_cast<CWfiLog*>(pParam);

	while (TRUE)
	{
		switch (WaitForSingleObject(pLog->m_hStop, 10000))
		{
		case WAIT_OBJECT_0 + 0:
			return 0;
			break;

		case WAIT_TIMEOUT:
			EnterCriticalSection(&pLog->m_CSLog);

			if (pLog->m_bFlushNeeded && pLog->m_hLogFile != INVALID_HANDLE_VALUE)
				FlushFileBuffers(pLog->m_hLogFile);

			LeaveCriticalSection(&pLog->m_CSLog);
		}
	}
}
//---------------------------------------------------------------------------

BOOL CWfiLog::CreateLogFile()
{
	WCHAR szPath[MAX_PATH + 1];

	GetSystemDirectoryW(szPath, LENGTHOF(szPath));
	wcscat_s(szPath, LENGTHOF(szPath), L"\\wfimon.log");

	m_hLogFile = CreateFileW(szPath, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);

	if (m_hLogFile == INVALID_HANDLE_VALUE)
		return FALSE;

	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		SetFilePointer(m_hLogFile, 0, NULL, FILE_END);
	}
	else
	{
		DWORD wri;
		WriteFile(m_hLogFile, &BOM, sizeof(BOM), &wri, NULL);
		m_bFlushNeeded = TRUE;
	}

	return TRUE;
}
//---------------------------------------------------------------------------

void CWfiLog::RotateLogs()
{
	if (m_hLogFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hLogFile);
		m_hLogFile = INVALID_HANDLE_VALUE;
	}

	for (int n = 9; n >= 0; n--)
	{
		WCHAR szOldFname[32];
		WCHAR szNewFname[32];

		WCHAR szOldPath[MAX_PATH + 1];
		WCHAR szNewPath[MAX_PATH + 1];

		GetSystemDirectoryW(szOldPath, LENGTHOF(szOldPath));

		if (n == 0)
		{
			wcscat_s(szOldPath, LENGTHOF(szOldPath), L"\\wfimon.log");
		}
		else
		{
			swprintf_s(szOldFname, LENGTHOF(szOldFname), L"\\wfimon.%i.log", n);
			wcscat_s(szOldPath, LENGTHOF(szOldPath), szOldFname);
		}

		if (n == 9)
		{
			DeleteFileW(szOldPath);
		}
		else
		{
			GetSystemDirectoryW(szNewPath, LENGTHOF(szNewPath));

			swprintf_s(szNewFname, LENGTHOF(szNewFname), L"\\wfimon.%i.log", n + 1);
			wcscat_s(szNewPath, LENGTHOF(szNewPath), szNewFname);

			MoveFileW(szOldPath, szNewPath);
		}
	}
}
//---------------------------------------------------------------------------

void CWfiLog::SetLogLevel(DWORD nLevel)
{
	if (nLevel < LOGLEVEL_MIN)
		nLevel = LOGLEVEL_MIN;
	else if (nLevel > LOGLEVEL_MAX)
		nLevel = LOGLEVEL_MAX;

	m_nLogLevel = nLevel;
}
//---------------------------------------------------------------------------

void CWfiLog::Always(LPCWSTR szFormat, ...)
{
	CHECK_LEVEL(LOGLEVEL_NONE);

	va_list args;

	va_start(args, szFormat);
	LogArgs(szFormat, L"NONE", args);
	va_end(args);
}
//---------------------------------------------------------------------------

void CWfiLog::Debug(LPCWSTR szFormat, ...)
{
	CHECK_LEVEL(LOGLEVEL_DEBUG);

	va_list args;

	va_start(args, szFormat);
	LogArgs(szFormat, L"DEBUG", args);
	va_end(args);
}
//---------------------------------------------------------------------------

void CWfiLog::Info(LPCWSTR szFormat, ...)
{
	CHECK_LEVEL(LOGLEVEL_ERRORS);

	va_list args;

	va_start(args, szFormat);
	LogArgs(szFormat, L"INFO", args);
	va_end(args);
}
//---------------------------------------------------------------------------

void CWfiLog::Done(LPCWSTR szFormat, ...)
{
	CHECK_LEVEL(LOGLEVEL_ERRORS);

	va_list args;

	va_start(args, szFormat);
	LogArgs(szFormat, L"DONE", args);
	va_end(args);
}
//---------------------------------------------------------------------------

void CWfiLog::Warn(LPCWSTR szFormat, ...)
{
	CHECK_LEVEL(LOGLEVEL_ERRORS);

	va_list args;

	va_start(args, szFormat);
	LogArgs(szFormat, L"WARN", args);
	va_end(args);
}
//---------------------------------------------------------------------------

void CWfiLog::Error(LPCWSTR szFormat, ...)
{
	CHECK_LEVEL(LOGLEVEL_ERRORS);

	va_list args;

	va_start(args, szFormat);
	LogArgs(szFormat, L"ERROR", args);
	va_end(args);
}
//---------------------------------------------------------------------------

void CWfiLog::Critical(LPCWSTR szFormat, ...)
{
	CHECK_LEVEL(LOGLEVEL_ERRORS);

	va_list args;

	va_start(args, szFormat);
	LogArgs(szFormat, L"CRITICAL", args);
	va_end(args);
}
//---------------------------------------------------------------------------

void CWfiLog::LogArgs(LPCWSTR szFormat, LPCWSTR szType, va_list args)
{
	WCHAR szMessage[MAXLOGLINE];

	vswprintf_s(szMessage, LENGTHOF(szMessage), szFormat, args);
	Log(szType, szMessage);
}
//---------------------------------------------------------------------------

void CWfiLog::Log(LPCWSTR szType, LPCWSTR szMessage)
{
	SYSTEMTIME st;
	DWORD wri;
	const DWORD MAXLOGSIZE = 10 * 1024 * 1024;

	GetLocalTime(&st);

	int len = swprintf_s(m_szBuffer, LENGTHOF(m_szBuffer),
		L"%02i-%02i-%04i %02i:%02i:%02i.%03i  [%s] %s\r\n",
		st.wDay, st.wMonth, st.wYear,
		st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
		szType,
		szMessage
	);

	if (len > 0)
	{
		EnterCriticalSection(&m_CSLog);

		DWORD dwSize, dwSizeHigh;
		dwSize = GetFileSize(m_hLogFile, &dwSizeHigh);
		if (dwSize >= MAXLOGSIZE || dwSizeHigh > 0)
		{
			RotateLogs();
			if (!CreateLogFile())
				goto LExit;
		}

		WriteFile(m_hLogFile, m_szBuffer, len * sizeof(WCHAR), &wri, NULL);
		m_bFlushNeeded = TRUE;

	LExit:
		LeaveCriticalSection(&m_CSLog);
	}
}
//---------------------------------------------------------------------------
