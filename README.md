# ProcessHider

### Under Development

There are multiple ways of retrieving a list of running processes but by hooking NtQuerySystemInformation, we cover most of them.
So what ProcessHider does is, It hooks NtQuerySystemInformation so when it is called our hooked function manipulates the process list and removes our process from that list and thus hiding it from Task Manager.

For this, I have used <a href = "https://github.com/TsudaKageyu/minhook">Minhook Library</a>. The Core part of ProcessHider is the DLL itself. The Injector is just one of the ways to load the DLL into Task Manager. There are a lot of ways of injecting the DLL into the remote process but for the sake of simplicity I have used the CreateRemoteThread method. <b>This still needs alot of improvements and only hides the hardcoded process in DLL for now. Will add the required functions soon.</b>

### Usage:
	- Open the Solution file in Visual Studio.
	- Compile Both Projects.
	- Make Sure the DLL is in same directory as the Injector.
	- Run the Injector.
