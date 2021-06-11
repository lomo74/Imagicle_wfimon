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

//funzioni del port monitor. I membri di MONITOR2 punteranno a queste funzioni

BOOL WINAPI WfiEnumPorts(HANDLE hMonitor, LPWSTR pName, DWORD Level, LPBYTE pPorts,
						 DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned);

BOOL WINAPI WfiOpenPort(HANDLE hMonitor, LPWSTR pName, PHANDLE pHandle);

BOOL WINAPI WfiStartDocPort(HANDLE hPort, LPWSTR pPrinterName, DWORD JobId,
							DWORD Level, LPBYTE pDocInfo);

BOOL WINAPI WfiWritePort(HANDLE hPort, LPBYTE pBuffer, 
						 DWORD cbBuf, LPDWORD pcbWritten);

BOOL WINAPI WfiReadPort(HANDLE hPort, LPBYTE pBuffer,
						DWORD cbBuffer, LPDWORD pcbRead);

BOOL WINAPI WfiEndDocPort(HANDLE hPort);

BOOL WINAPI WfiClosePort(HANDLE hPort);

BOOL WINAPI WfiXcvOpenPort(HANDLE hMonitor, LPCWSTR pszObject, 
						   ACCESS_MASK GrantedAccess, PHANDLE phXcv);

DWORD WINAPI WfiXcvDataPort(HANDLE hXcv, LPCWSTR pszDataName, PBYTE pInputData,
							DWORD cbInputData, PBYTE pOutputData, DWORD cbOutputData,
							PDWORD pcbOutputNeeded);

BOOL WINAPI WfiXcvClosePort(HANDLE hXcv);

VOID WINAPI WfiShutdown(HANDLE hMonitor);

extern "C"
{
	BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved);
}
