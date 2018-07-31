#include <Windows.h>
#include <iostream>
#include <string>

using namespace std;

void find_and_inject(string dll_path)
{
	// TODO: Find Task Manager and Inject DLL
}

void map_process_name(string process) {
	// TODO: Map process to hide using File Mapping so it can be accessed by DLL
}

int main()
{
	string dll_path, process;
	cout << "Enter Process To Hide" << endl << "- ";
	cin >> process;
	map_process_name(process);
	cout << " Enter Full Path To ProcessHider.dll" << endl << "- ";
	cin >> dll_path;
	find_and_inject(dll_path);
	return 0;
}