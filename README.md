# ProcessHider

### Under Development

The main purpose of this project is to show how easy it is to hook Nt functions (or incase any function) with use of existing hooking libraries. For this, I have used <a href = "https://github.com/TsudaKageyu/minhook">Minhook</a>. The Core part of ProcessHider is the DLL itself. The Injector is just one of the ways to load the DLL into Task Manager. There are a lot of ways of injecting the DLL into the remote process but for the sake of simplicity I have used the CreateRemoteThread method. <b>This still needs alot of improvements.</b>

### Usage:
	- Open the Solution file in Visual Studio.
	- Compile Both Projects.
	- Make Sure the DLL is in same directory as the Injector.
	- Run the Injector.
