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

#pragma once

#include <windows.h>

#define MAXLOGLINE 8192

#define LOGLEVEL_NONE		0
#define LOGLEVEL_ERRORS		1
#define LOGLEVEL_DEBUG		2
#define LOGLEVEL_MIN		LOGLEVEL_NONE
#define LOGLEVEL_MAX		LOGLEVEL_DEBUG

class CWfiLog
{
public:
	CWfiLog();
	virtual ~CWfiLog();

protected:
	void LogArgs(LPCWSTR szFormat, LPCWSTR szType, va_list args);
	void Log(LPCWSTR szType, LPCWSTR szMessage);
	BOOL CreateLogFile();
	void RotateLogs();

public:
	void SetLogLevel(DWORD nLevel);
	DWORD GetLogLevel() const { return m_nLogLevel; }
	void Always(LPCWSTR szFormat, ...);
	void Debug(LPCWSTR szFormat, ...);
	void Info(LPCWSTR szFormat, ...);
	void Done(LPCWSTR szFormat, ...);
	void Warn(LPCWSTR szFormat, ...);
	void Error(LPCWSTR szFormat, ...);
	void Critical(LPCWSTR szFormat, ...);

private:
	DWORD m_nLogLevel;
	HANDLE m_hLogFile;
	HANDLE m_hStop;
	HANDLE m_hThread;
	WCHAR m_szBuffer[MAXLOGLINE];
	CRITICAL_SECTION m_CSLog;
	BOOL m_bFlushNeeded;

	static DWORD WINAPI FlushThread(LPVOID pParam);
};

extern CWfiLog* g_pLog;
