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
#include "portlist.h"
#include "pattern.h"
#include "log.h"
#include "..\common\autoclean.h"
#include "..\common\monutils.h"

CPortList* g_pPortList = NULL;
LPCWSTR CPortList::szLogLevelKey = L"LogLevel";

//-------------------------------------------------------------------------------------
CPortList::CPortList(LPCWSTR szPortMonitorName, LPCWSTR szPortDesc)
{
	InitializeCriticalSection(&m_CSPortList);
	wcscpy_s(m_szMonitorName, LENGTHOF(m_szMonitorName), szPortMonitorName);
	wcscpy_s(m_szPortDesc, LENGTHOF(m_szPortDesc), szPortDesc);
	m_pFirstPortRec = NULL;
}

//-------------------------------------------------------------------------------------
CPortList::~CPortList()
{
	LPPORTREC pNext = NULL;

	while (m_pFirstPortRec)
	{
		pNext = m_pFirstPortRec->m_pNext;
		delete m_pFirstPortRec;
		m_pFirstPortRec = pNext;
	}

	DeleteCriticalSection(&m_CSPortList);
}

//-------------------------------------------------------------------------------------
CPort* CPortList::FindPort(LPCWSTR szPortName)
{
	CAutoCriticalSection acs(GetCriticalSection());

	LPPORTREC pPortRec = m_pFirstPortRec;

	while (pPortRec)
	{
		if (_wcsicmp(pPortRec->m_pPort->PortName(), szPortName) == 0)
			break;
		pPortRec = pPortRec->m_pNext;
	}

	return pPortRec
		? pPortRec->m_pPort
		: NULL;
}

//-------------------------------------------------------------------------------------
DWORD CPortList::GetPortSize(LPCWSTR szPortName, DWORD dwLevel)
{
	DWORD cb = 0;

	WORD len1, len2, len3;
	DWORD totlen;

	switch (dwLevel)
	{
	case 1:
		len1 = static_cast<WORD>(wcslen(szPortName) + 1);
		totlen = len1;
		cb = sizeof(PORT_INFO_1W) +
			totlen * sizeof(WCHAR);
		break;
	case 2:
		len1 = static_cast<WORD>(wcslen(szPortName) + 1);
		len2 = static_cast<WORD>(wcslen(m_szMonitorName) + 1);
		len3 = static_cast<WORD>(wcslen(m_szPortDesc) + 1);
		totlen = len1 + len2 + len3;
		cb = sizeof(PORT_INFO_2W) +
			totlen * sizeof(WCHAR);
		break;
	default:
		break;
	}

	return cb;
}

//-------------------------------------------------------------------------------------
LPBYTE CPortList::CopyPortToBuffer(CPort* pPort, DWORD dwLevel, LPBYTE pStart, LPBYTE pEnd)
{
	size_t len = 0;

	switch (dwLevel)
	{
	case 1:
		{
			PORT_INFO_1W* pPortInfo = (PORT_INFO_1W*)pStart;
			len = wcslen(pPort->PortName()) + 1;
			pEnd -= len * sizeof(WCHAR);
			wcscpy_s((LPWSTR)pEnd, len, pPort->PortName());
			pPortInfo->pName = (LPWSTR)pEnd;
			break;
		}
	case 2:
		{
			PORT_INFO_2W* pPortInfo = (PORT_INFO_2W*)pStart;
			len = wcslen(m_szMonitorName) + 1;
			pEnd -= len * sizeof(WCHAR);
			wcscpy_s((LPWSTR)pEnd, len, m_szMonitorName);
			pPortInfo->pMonitorName = (LPWSTR)pEnd;

			len = wcslen(m_szPortDesc) + 1;
			pEnd -= len * sizeof(WCHAR);
			wcscpy_s((LPWSTR)pEnd, len, m_szPortDesc);
			pPortInfo->pDescription = (LPWSTR)pEnd;

			len = wcslen(pPort->PortName()) + 1;
			pEnd -= len * sizeof(WCHAR);
			wcscpy_s((LPWSTR)pEnd, len, pPort->PortName());
			pPortInfo->pPortName = (LPWSTR)pEnd;

			pPortInfo->fPortType = 0;
			pPortInfo->Reserved = 0;
			break;
		}
	default:
		break;
	}

    return pEnd;
}

//-------------------------------------------------------------------------------------
BOOL CPortList::EnumPorts(HANDLE hMonitor, LPCWSTR pName, DWORD Level, LPBYTE pPorts,
	DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
{
	UNREFERENCED_PARAMETER(pName);
	UNREFERENCED_PARAMETER(hMonitor);

	CAutoCriticalSection acs(GetCriticalSection());

	LPPORTREC pPortRec = m_pFirstPortRec;

	DWORD cb = 0;
	while (pPortRec)
	{
		cb += GetPortSize(pPortRec->m_pPort->PortName(), Level);
		pPortRec = pPortRec->m_pNext;
	}

	*pcbNeeded = cb;

	if (cbBuf < *pcbNeeded)
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	LPBYTE pEnd = pPorts + cbBuf;
	*pcReturned = 0;
	pPortRec = m_pFirstPortRec;
	while (pPortRec)
	{
		pEnd = CopyPortToBuffer(pPortRec->m_pPort, Level, pPorts, pEnd);
		switch (Level)
		{
		case 1:
			pPorts += sizeof(PORT_INFO_1W);
			break;
		case 2:
			pPorts += sizeof(PORT_INFO_2W);
			break;
		default:
			{
				SetLastError(ERROR_INVALID_LEVEL);
				return FALSE;
			}
		}
		(*pcReturned)++;

		pPortRec = pPortRec->m_pNext;
	}

	return TRUE;
}

//-------------------------------------------------------------------------------------
void CPortList::AddWfiPort(LPCWSTR szPortName)
{
	AddWfiPort(new CPort(szPortName));
}

//-------------------------------------------------------------------------------------
void CPortList::AddWfiPort(CPort* pNewPort)
{
	CAutoCriticalSection acs(GetCriticalSection());

	LPPORTREC pPortRec = new PORTREC;

	pPortRec->m_pPort = pNewPort;
	pPortRec->m_pNext = m_pFirstPortRec;
	m_pFirstPortRec = pPortRec;

	g_pLog->Info(L"CPortList::AddWfiPort: port %s up and running", pNewPort->PortName());
}

//-------------------------------------------------------------------------------------
void CPortList::LoadConfiguration()
{
#ifndef _DEBUG
	PMONITORREG pReg = g_pMonitorInit->pMonitorReg;
	HKEY hRoot = (HKEY)g_pMonitorInit->hckRegistryRoot;
	DWORD nLogLevel;
	DWORD cbData;

	cbData = sizeof(nLogLevel);
	if (pReg->fpQueryValue(hRoot, szLogLevelKey, NULL, (LPBYTE)&nLogLevel, &cbData,
		g_pMonitorInit->hSpooler) != ERROR_SUCCESS)
	{
		nLogLevel = LOGLEVEL_DEBUG;
	}

	g_pLog->SetLogLevel(nLogLevel);
#endif

	AddWfiPort(L"WFI:");
}

//-------------------------------------------------------------------------------------
void CPortList::SaveConfiguration()
{
	HANDLE hToken = NULL;
	if (IsUACEnabled())
	{
		g_pLog->Debug(L"CPortList::SaveConfiguration: running on UAC enabled OS, switching to local system");
		OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, TRUE, &hToken);
		RevertToSelf();
	}

#ifndef _DEBUG
	PMONITORREG pReg = g_pMonitorInit->pMonitorReg;
	HKEY hRoot = (HKEY)g_pMonitorInit->hckRegistryRoot;

	DWORD nLogLevel = g_pLog->GetLogLevel();
	pReg->fpSetValue(hRoot, szLogLevelKey, REG_DWORD, (LPBYTE)&nLogLevel, sizeof(nLogLevel),
		g_pMonitorInit->hSpooler);
#endif

	//let's revert to unprivileged user
	if (hToken)
	{
		SetThreadToken(NULL, hToken);
		CloseHandle(hToken);
		g_pLog->Debug(L"CPortList::SaveConfiguration: reverting to unprivileged user");
	}
}
