#include <Windows.h>
#include "../include/MinHook.h"
#include "nt_structs.h"

#pragma comment(lib, "../include/libMinHook.x64.lib")

PNT_QUERY_SYSTEM_INFORMATION Original_NtQuerySystemInformation;
PNT_QUERY_SYSTEM_INFORMATION New_NtQuerySystemInformation;


NTSTATUS WINAPI Hooked_NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	
}

void set_nt_hook()
{
	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");

	Original_NtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(ntdll, "NtQuerySystemInformation");

	if (MH_Initialize() != MH_OK) { return; }

	if(MH_CreateHook(Original_NtQuerySystemInformation, &Hooked_NtQuerySystemInformation, 
		(LPVOID*) &New_NtQuerySystemInformation) != MH_OK) { return; }

	MH_EnableHook(Original_NtQuerySystemInformation);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		set_nt_hook();
		break;
	}

	return true;
}