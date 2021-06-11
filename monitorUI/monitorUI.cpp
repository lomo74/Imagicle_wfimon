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
#include "monitorUI.h"
#include "..\common\config.h"
#include "..\common\defs.h"
#include "..\common\autoclean.h"
#include "..\common\version.h"
#include "resource.h"

HINSTANCE g_hInstance = NULL;

static LPWSTR szLogLevelNone = L"None";
static LPWSTR szLogLevelErrors = L"Errors";
static LPWSTR szLogLevelDebug = L"Debug";

//-------------------------------------------------------------------------------------
static void UpdateCaption(HWND hDlg)
{
	WCHAR szCaption[256];
	WCHAR szOldCaption[256];

	GetWindowTextW(hDlg, szOldCaption, LENGTHOF(szCaption));
	swprintf_s(szCaption, LENGTHOF(szCaption), L"WFIMON %s - %s", szVersionShort, szOldCaption);
	SetWindowTextW(hDlg, szCaption);
}

//-------------------------------------------------------------------------------------
static BOOL CALLBACK MonitorUIDlgProc(HWND hDlg, UINT uMessage, WPARAM wParam, LPARAM lParam)
{
	HWND hWnd;
	static LPPORTCONFIG ppc = NULL;

	switch (uMessage)
	{
	case WM_INITDIALOG:
		UpdateCaption(hDlg);

		ppc = (LPPORTCONFIG)lParam;
		//Log Level
		hWnd = GetDlgItem(hDlg, ID_CBLOGLEVEL);
		if (hWnd)
		{
			SendMessageW(hWnd, CB_ADDSTRING, 0, (LPARAM)szLogLevelNone);
			SendMessageW(hWnd, CB_ADDSTRING, 0, (LPARAM)szLogLevelErrors);
			SendMessageW(hWnd, CB_ADDSTRING, 0, (LPARAM)szLogLevelDebug);
			SendMessageW(hWnd, CB_SETCURSEL, ppc->nLogLevel, 0);
		}
		return TRUE;
	case WM_COMMAND:
		_ASSERTE(ppc != NULL);
		switch (LOWORD(wParam))
		{
		case IDOK:
		{
			//Log Level
			hWnd = GetDlgItem(hDlg, ID_CBLOGLEVEL);
			if (hWnd)
				ppc->nLogLevel = (int)SendMessageW(hWnd, CB_GETCURSEL, 0, 0);

			EndDialog(hDlg, IDOK);
			return TRUE;
		}
		case IDCANCEL:
			EndDialog(hDlg, IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiAddPortUI(PCWSTR pszServer, HWND hWnd, PCWSTR pszMonitorNameIn,
						 PWSTR* ppszPortNameOut)
{
	UNREFERENCED_PARAMETER(pszServer);
	UNREFERENCED_PARAMETER(hWnd);
	UNREFERENCED_PARAMETER(pszMonitorNameIn);
	UNREFERENCED_PARAMETER(ppszPortNameOut);

	SetLastError(ERROR_CANCELLED);
	return FALSE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiConfigurePortUI(PCWSTR pszServer, HWND hWnd, PCWSTR pszPortName)
{
	if (!hWnd || !IsWindow(hWnd))
	{
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	if (pszServer != NULL)
	{
		MessageBoxW(hWnd, szMsgNoConfigOnRemoteSvr, szAppTitle, MB_OK);
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	size_t len = 9 + wcslen(pszPortName) + 1;
	LPWSTR pszPrinter;
	if ((pszPrinter = new WCHAR[len]) == NULL)
	{
		SetLastError(ERROR_OUTOFMEMORY);
		return FALSE;
	}
	swprintf_s(pszPrinter, len, L",XcvPort %ls", pszPortName);
	CPrinterHandle printer(pszPrinter, SERVER_ACCESS_ADMINISTER);
	delete[] pszPrinter;

	if (!printer.Handle())
	{
		SetLastError(ERROR_CAN_NOT_COMPLETE);
		return FALSE;
	}

	BOOL bRes = FALSE;
	PORTCONFIG pc = { 0 };
	DWORD cbOutputNeeded, dwStatus;

	bRes = XcvDataW(printer, L"GetConfig", NULL, 0,
		(PBYTE)&pc, sizeof(pc), &cbOutputNeeded, &dwStatus);
	if (!bRes || dwStatus != ERROR_SUCCESS)
	{
		SetLastError(dwStatus);
		return FALSE;
	}

	//chiediamo la configurazione al nostro utente
	if (DialogBoxParamW(g_hInstance, MAKEINTRESOURCE(IDD_MONITORUI),
		hWnd, (DLGPROC)MonitorUIDlgProc, (LPARAM)&pc) == IDCANCEL)
	{
		SetLastError(ERROR_CANCELLED);
		return FALSE;
	}

	//passiamo la configurazione al port monitor
	bRes = XcvDataW(printer, L"SetConfig", (PBYTE)&pc, sizeof(pc),
		NULL, 0, &cbOutputNeeded, &dwStatus);
	if (!bRes || dwStatus != ERROR_SUCCESS)
	{
		SetLastError(dwStatus);
		return FALSE;
	}

	//tutto OK, usciamo con TRUE
	return TRUE;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI WfiDeletePortUI(PCWSTR pszServer, HWND hWnd, PCWSTR pszPortName)
{
	UNREFERENCED_PARAMETER(pszServer);
	UNREFERENCED_PARAMETER(hWnd);
	UNREFERENCED_PARAMETER(pszPortName);

	SetLastError(ERROR_CANCELLED);
	return FALSE;
}

//-------------------------------------------------------------------------------------
PMONITORUI WINAPI InitializePrintMonitorUI()
{
	static MONITORUI themonui = { 0 };

	themonui.dwMonitorUISize = sizeof(themonui);
	themonui.pfnAddPortUI = WfiAddPortUI;
	themonui.pfnConfigurePortUI = WfiConfigurePortUI;
	themonui.pfnDeletePortUI = WfiDeletePortUI;

	return &themonui;
}

//-------------------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(lpvReserved);

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		{
			g_hInstance = hinstDLL;
// see here http://msdn.microsoft.com/en-us/library/ms682659%28v=vs.85%29.aspx
// why the following call should not be done
//			DisableThreadLibraryCalls((HMODULE)hinstDLL);
			break;
		}
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}