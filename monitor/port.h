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

#include <LMCons.h>
#include "pattern.h"
#include "..\common\config.h"
#include "..\common\defs.h"

class CPort
{
private:
	static SYSTEMTIME m_DefSysTime;

	void Initialize();
	void Initialize(LPCWSTR szPortName);
	void StartExe(LPCWSTR szExeName, LPCWSTR szWorkingDir, LPWSTR szCmdLine, BOOL bTSEnabled, DWORD dwSessionId);

public:
	CPort();
	CPort(LPCWSTR szPortName);
	virtual ~CPort();
	CPattern* GetPattern() const { return m_pPattern; }
	void SetFilePatternString(LPCWSTR szPattern);
	BOOL StartJob(DWORD nJobId, LPWSTR szJobTitle, LPWSTR szPrinterName);
	DWORD CreateOutputFile();
	BOOL WriteToFile(LPCVOID lpBuffer, DWORD cbBuffer,
		LPDWORD pcbWritten);
	BOOL EndJob();
	void SetConfig(LPPORTCONFIG pConfig);

public:
	LPCWSTR PortName() const { return m_szPortName; }
	LPCWSTR OutputPath() const { return m_szOutputPath; }
	LPCWSTR ExecPath() const { return (m_szExecPath && *m_szExecPath ? m_szExecPath : NULL); }
	LPCWSTR GUIPath() const { return m_szGUIPath; }
	LPCWSTR FilePattern() const;
	LPWSTR PrinterName() const { return m_szPrinterName; }
	DWORD JobId() const { return m_nJobId; }
	LPWSTR JobTitle() const { return m_pJobInfo2 ? m_pJobInfo2->pDocument : (LPWSTR)L""; }
	LPCWSTR UserName() const { return m_pJobInfo2 ? m_pJobInfo2->pUserName : (LPWSTR)L""; }
	LPCWSTR ComputerName() const;
	LPWSTR FileName() const { return (LPWSTR)m_szFileName; }
	LPWSTR Path() const { return (LPWSTR)m_szParent; }
	LPWSTR Bin() const;
	DWORD TotalPages() const { return m_pJobInfo2 ? (m_pJobInfo2->TotalPages ? m_pJobInfo2->TotalPages : m_pJobInfo2->PagesPrinted) : 0; }
	DWORD Priority() const { return m_pJobInfo2 ? m_pJobInfo2->Priority : DEF_PRIORITY; }
	SYSTEMTIME& Submitted() const { return m_pJobInfo2 ? m_pJobInfo2->Submitted : m_DefSysTime; }

private:
	DWORD RecursiveCreateFolder(LPCWSTR szPath);
	BOOL GetJobInfo();

private:
	WCHAR m_szPortName[MAX_PATH + 1];
	WCHAR m_szOutputPath[MAX_PATH + 1];
	WCHAR m_szExecPath[MAX_PATH + 1];
	WCHAR m_szGUIPath[MAX_PATH + 1];
	LPWSTR m_szPrinterName;
	DWORD m_cchPrinterName;
	CPattern* m_pPattern;
	WCHAR m_szFileName[MAX_PATH + 1];
	HANDLE m_hFile;
	DWORD m_nJobId;
	JOB_INFO_2W* m_pJobInfo2;
	DWORD m_cbJobInfo2;
	WCHAR m_szParent[MAX_PATH + 1];
	HANDLE m_hToken;
	BOOL m_bRestrictedToken;
	BOOL m_bLogonInvalidated;
};
