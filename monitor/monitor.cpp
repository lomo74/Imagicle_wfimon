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
#include "monitor.h"
#include "pattern.h"
#include "portlist.h"
#include "log.h"
#include "..\common\autoclean.h"
#include "..\common\monutils.h"
#include "..\common\config.h"
#include "..\common\defs.h"

//-------------------------------------------------------------------------------------
typedef struct tagXCVDATA
{
	tagXCVDATA()
	{
		pPort = NULL;
		bDeleting = FALSE;
		GrantedAccess = 0;
	}
	CPort* pPort;
	BOOL bDeleting;
	ACCESS_MASK GrantedAccess;
} XCVDATA, *LPXCVDATA;

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiEnumPorts(HANDLE hMonitor, LPWSTR pName, DWORD Level, LPBYTE pPorts, 
						 DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
{
	return g_pPortList->EnumPorts(hMonitor, pName, Level, pPorts,
		cbBuf, pcbNeeded, pcReturned);
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiOpenPort(HANDLE hMonitor, LPWSTR pName, PHANDLE pHandle)
{
	UNREFERENCED_PARAMETER(hMonitor);

	g_pLog->Debug(L"WfiOpenPort called (%s)", pName);

	CPort* pPort = g_pPortList->FindPort(pName);
	*pHandle = (HANDLE)pPort;
	if (!pPort)
	{
		g_pLog->Critical(L"WfiOpenPort: can't find port %s", pName);
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	g_pLog->Debug(L"WfiOpenPort returning TRUE (%s)", pName);

	return TRUE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiStartDocPort(HANDLE hPort, LPWSTR pPrinterName, DWORD JobId,
						    DWORD Level, LPBYTE pDocInfo)
{
	UNREFERENCED_PARAMETER(Level);

	if (!hPort || !pDocInfo)
	{
		g_pLog->Critical(L"WfiStartDocPort: invalid parameter (hPort = %X pDocInfo = %X)", hPort, pDocInfo);
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	CPort* pPort = (CPort*)hPort;
	DOC_INFO_1W* pdi = (DOC_INFO_1W*)pDocInfo;

	g_pLog->Debug(L"WfiStartDocPort called (%s)", pPort->PortName());

	CAutoCriticalSection acs(g_pPortList->GetCriticalSection());

	/*set initial job data*/
	if (!pPort->StartJob(JobId, pdi->pDocName, pPrinterName))
	{
		g_pLog->Critical(L"WfiStartDocPort: can't start print job");
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	/*create output file or pipe*/
	DWORD res;
	if ((res = pPort->CreateOutputFile()) != 0)
	{
		g_pLog->Critical(L"WfiStartDocPort: can't create output file");
		SetLastError(res);
		return FALSE;
	}
	
	g_pLog->Debug(L"WfiStartDocPort returning TRUE (%s)", pPort->PortName());

	return TRUE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiWritePort(HANDLE hPort, LPBYTE pBuffer, 
						 DWORD cbBuf, LPDWORD pcbWritten)
{
	if (!hPort)
	{
		g_pLog->Critical(L"WfiWritePort: invalid parameter (hPort = %X)", hPort);
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	CPort* pPort = (CPort*)hPort;

	g_pLog->Debug(L"WfiWritePort called (%s)", pPort->PortName());

	CAutoCriticalSection acs(g_pPortList->GetCriticalSection());

	/*write was unsuccessful, tell the spooler to restart and pause job*/
	if (!pPort->WriteToFile(pBuffer, cbBuf, pcbWritten))
	{
		g_pLog->Critical(L"WfiWritePort: can't write to output file");

		HANDLE hPrinter;

		if (OpenPrinterW(pPort->PrinterName(), &hPrinter, NULL))
		{
			g_pLog->Error(L"WfiWritePort: pausing job %u on %s",
				pPort->JobId(), pPort->PrinterName());
			SetJobW(hPrinter, pPort->JobId(), 0, NULL, JOB_CONTROL_RESTART);
			SetJobW(hPrinter, pPort->JobId(), 0, NULL, JOB_CONTROL_PAUSE);
			ClosePrinter(hPrinter);
		}
		else
		{
			g_pLog->Critical(L"WfiWritePort: can't pause job %u on %s",
				pPort->JobId(), pPort->PrinterName());
		}

		return FALSE;
	}

	g_pLog->Debug(L"WfiWritePort returning TRUE (%s)", pPort->PortName());

	return TRUE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiReadPort(HANDLE hPort, LPBYTE pBuffer,
					    DWORD cbBuffer, LPDWORD pcbRead)
{
	UNREFERENCED_PARAMETER(hPort);
	UNREFERENCED_PARAMETER(pBuffer);
	UNREFERENCED_PARAMETER(cbBuffer);
	UNREFERENCED_PARAMETER(pcbRead);

	/*no reading from this port*/
	SetLastError(ERROR_INVALID_HANDLE);
	return FALSE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiEndDocPort(HANDLE hPort)
{
	if (!hPort)
	{
		g_pLog->Critical(L"WfiEndDocPort: invalid parameter (hPort = %X)", hPort);
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	CPort* pPort = (CPort*)hPort;

	g_pLog->Debug(L"WfiEndDocPort called (%s)", pPort->PortName());

	CAutoCriticalSection acs(g_pPortList->GetCriticalSection());

	BOOL bRet = pPort->EndJob();

	g_pLog->Debug(L"WfiEndDocPort returning %s (%s)", bRet ? L"TRUE" : L"FALSE", pPort->PortName());

	return bRet;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiClosePort(HANDLE hPort)
{
	UNREFERENCED_PARAMETER(hPort);

	return TRUE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiXcvOpenPort(HANDLE hMonitor, LPCWSTR pszObject, 
						   ACCESS_MASK GrantedAccess, PHANDLE phXcv)
{
	UNREFERENCED_PARAMETER(hMonitor);

	g_pLog->Debug(L"WfiXcvOpenPort called (%s), GrantedAccess = %u",
		(LPWSTR)pszObject, GrantedAccess);

	LPXCVDATA pXCVDATA = new XCVDATA;

	*phXcv = (HANDLE)pXCVDATA;

	if (pszObject)
		pXCVDATA->pPort = g_pPortList->FindPort((LPWSTR)pszObject);

	pXCVDATA->GrantedAccess = GrantedAccess;

	g_pLog->Debug(L"WfiXcvOpenPort returning TRUE (%s)", (LPWSTR)pszObject);

	return TRUE;
}

//-------------------------------------------------------------------------------------
DWORD WINAPI WfiXcvDataPort(HANDLE hXcv, LPCWSTR pszDataName, PBYTE pInputData,
						    DWORD cbInputData, PBYTE pOutputData, DWORD cbOutputData,
						    PDWORD pcbOutputNeeded)
{
	g_pLog->Debug(L"WfiXcvDataPort called (%s)", pszDataName);

	LPXCVDATA pXCVDATA = (LPXCVDATA)hXcv;

	if (wcscmp(pszDataName, L"AddPort") == 0)
	{
		return ERROR_CAN_NOT_COMPLETE;
	}
	else if (wcscmp(pszDataName, L"DeletePort") == 0)
	{
		return ERROR_CAN_NOT_COMPLETE;
	}
	else if (wcscmp(pszDataName, L"PortDeleted") == 0)
	{
		return ERROR_CAN_NOT_COMPLETE;
	}
	else if (wcscmp(pszDataName, L"PortExists") == 0)
	{
		LPWSTR szPortName = (LPWSTR)pInputData;
		DWORD needed, returned;
		if (EnumPorts(NULL, 1, NULL, 0, &needed, &returned) == 0 &&
			GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			LPBYTE pBuf;
			if ((pBuf = new BYTE[needed]) == NULL)
			{
				g_pLog->Critical(L"WfiXcvDataPort: out of memory");
				return ERROR_OUTOFMEMORY;
			}
			if (EnumPorts(NULL, 1, pBuf, needed, &needed, &returned))
			{
				PORT_INFO_1W* pPorts = (PORT_INFO_1W*)pBuf;
				while (returned--)
				{
					if (_wcsicmp(szPortName, pPorts->pName) == 0)
					{
						g_pLog->Debug(L"WfiXcvDataPort: port already exists (%s)", szPortName);
						*((BOOL*)pOutputData) = TRUE;
						break;
					}
					pPorts++;
				}
			}
			delete[] pBuf;
			g_pLog->Debug(L"WfiXcvDataPort returning ERROR_SUCCESS");
			return ERROR_SUCCESS;
		}
	}
	else if (wcscmp(pszDataName, L"SetConfig") == 0)
	{
		if (cbInputData < sizeof(PORTCONFIG))
		{
			g_pLog->Warn(L"WfiXcvDataPort returning ERROR_INSUFFICIENT_BUFFER");
			return ERROR_INSUFFICIENT_BUFFER;
		}
		if (pXCVDATA != NULL && pXCVDATA->pPort != NULL && pInputData != NULL)
		{
			if (!(pXCVDATA->GrantedAccess & SERVER_ACCESS_ADMINISTER))
			{
				g_pLog->Critical(L"WfiXcvDataPort returning ERROR_ACCESS_DENIED (pXCVDATA->GrantedAccess = %X)",
					pXCVDATA->GrantedAccess);
				return ERROR_ACCESS_DENIED;
			}
			LPPORTCONFIG ppc = (LPPORTCONFIG)pInputData;
			pXCVDATA->pPort->SetConfig(ppc);
			g_pPortList->SaveConfiguration();
			g_pLog->Debug(L"WfiXcvDataPort returning ERROR_SUCCESS");
			return ERROR_SUCCESS;
		}
		g_pLog->Critical(L"WfiXcvDataPort: bad arguments (pXCVDATA = %X pXCVDATA->pPort = %X pInputData = %X)",
			pXCVDATA, (pXCVDATA ? pXCVDATA->pPort : NULL), pInputData);
		return ERROR_BAD_ARGUMENTS;
	}
	else if (wcscmp(pszDataName, L"GetConfig") == 0)
	{
		*pcbOutputNeeded = sizeof(PORTCONFIG);
		if (*pcbOutputNeeded > cbOutputData)
		{
			g_pLog->Warn(L"WfiXcvDataPort returning ERROR_INSUFFICIENT_BUFFER");
			return ERROR_INSUFFICIENT_BUFFER;
		}
		if (pXCVDATA != NULL && pXCVDATA->pPort != NULL && pOutputData != NULL)
		{
			LPPORTCONFIG ppc = (LPPORTCONFIG)pOutputData;
			wcscpy_s(ppc->szPortName, LENGTHOF(ppc->szPortName), pXCVDATA->pPort->PortName());
			ppc->nLogLevel = g_pLog->GetLogLevel();
			g_pLog->Debug(L"WfiXcvDataPort returning ERROR_SUCCESS");
			return ERROR_SUCCESS;
		}
		g_pLog->Critical(L"WfiXcvDataPort: bad arguments (pXCVDATA = %X pXCVDATA->pPort = %X pOutputData = %X)",
			pXCVDATA, (pXCVDATA ? pXCVDATA->pPort : NULL), pOutputData);
		return ERROR_BAD_ARGUMENTS;
	}
	else if (wcscmp(pszDataName, L"MonitorUI") == 0)
	{
		static WCHAR szUIDLL[] = L"wfimonui.dll";
		*pcbOutputNeeded = sizeof(szUIDLL);
		if (cbOutputData < sizeof(szUIDLL))
		{
			g_pLog->Warn(L"WfiXcvDataPort returning ERROR_INSUFFICIENT_BUFFER");
			return ERROR_INSUFFICIENT_BUFFER;
		}
		CopyMemory(pOutputData, szUIDLL, sizeof(szUIDLL));
		g_pLog->Debug(L"WfiXcvDataPort returning ERROR_SUCCESS");
		return ERROR_SUCCESS;
	}

	g_pLog->Error(L"WfiXcvDataPort returning ERROR_CAN_NOT_COMPLETE");
	return ERROR_CAN_NOT_COMPLETE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiXcvClosePort(HANDLE hXcv)
{
	LPXCVDATA pXCVDATA = (LPXCVDATA)hXcv;

	g_pLog->Debug(L"WfiXcvClosePort called");

	//in caso di chiamata a XcvDataPort con metodo "DeletePort", si passa di qui 2 volte!
	//la prima volta, imposto, bDeleting = TRUE, così la memoria non viene liberata
	//poi, chiamo di nuovo XcvDataPort con metodo "PortDeleted", che imposta bDeleting = FALSE
	if (pXCVDATA && !pXCVDATA->bDeleting)
		delete pXCVDATA;

	g_pLog->Debug(L"WfiXcvClosePort returning TRUE");

	return TRUE;
}

//-------------------------------------------------------------------------------------
VOID WINAPI WfiShutdown(HANDLE hMonitor)
{
	UNREFERENCED_PARAMETER(hMonitor);
}

//-------------------------------------------------------------------------------------
LPMONITOR2 WINAPI InitializePrintMonitor2(_In_ PMONITORINIT pMonitorInit, _Out_ PHANDLE phMonitor)
{
	phMonitor = NULL;

	static MONITOR2 themon;

	if (!pMonitorInit->bLocal)
	{
		g_pLog->Critical(L"InitializePrintMonitor2: can't work on clusters");
		return NULL;
	}

	ZeroMemory(&themon, sizeof(MONITOR2));

	themon.cbSize = sizeof(MONITOR2);

	themon.pfnEnumPorts		= WfiEnumPorts;
	themon.pfnOpenPort		= WfiOpenPort;
	themon.pfnStartDocPort	= WfiStartDocPort;
	themon.pfnWritePort		= WfiWritePort;
	themon.pfnReadPort		= WfiReadPort;
	themon.pfnEndDocPort	= WfiEndDocPort;
	themon.pfnClosePort		= WfiClosePort;
	themon.pfnXcvOpenPort	= WfiXcvOpenPort;
	themon.pfnXcvDataPort	= WfiXcvDataPort;
	themon.pfnXcvClosePort	= WfiXcvClosePort;
	themon.pfnShutdown		= WfiShutdown;

	g_pMonitorInit = pMonitorInit;

	_ASSERTE(g_pPortList != NULL);

	g_pPortList->LoadConfiguration();

	g_pLog->Debug(L"InitializePrintMonitor2 successfully initialized WFIMON");

	return &themon;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(lpvReserved);
	UNREFERENCED_PARAMETER(hinstDLL);

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
#ifdef _DEBUG
		//Steady, ready, go. You have 20 seconds to attach your debugger to spoolsv
		Sleep(20000);
#endif
// see here http://msdn.microsoft.com/en-us/library/ms682659%28v=vs.85%29.aspx
// why the following call should not be done
//		DisableThreadLibraryCalls(hinstDLL);
		g_pLog = new CWfiLog();
		g_pLog->Always(L"*** WFIMON log start ***");
#ifdef _DEBUG
		//Force max log level in debug mode
		g_pLog->SetLogLevel(LOGLEVEL_DEBUG);
#else
		//Show only errors by default. We'll load the wanted log level from the registry
		g_pLog->SetLogLevel(LOGLEVEL_DEBUG);
#endif
		g_pPortList = new CPortList(szMonitorName, szDescription);
		break;

	case DLL_PROCESS_DETACH:
		delete g_pPortList;
		g_pLog->Always(L"*** WFIMON log end ***");
		delete g_pLog;
		break;
	}

	return TRUE;
}