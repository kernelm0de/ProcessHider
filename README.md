# ProcessHider

Process Hider uses Windows API Hooking to Hide a Process from TaskManager. It utilises <a href = "https://github.com/TsudaKageyu/minhook">Minhook Library</a> to hook NtQuerySystemInformation function so whenever NtQuerySystemInformation is called our function executes which removes the chosen process from Process List returned by the original function. 

There are 2 projects inside the repo, the main one is ProcessHider which produces the DLL that is injected inside Task Manager. The second one is the DLL injector whose main job is to inject the DLL and pass the name of the process to hide.

## To Compile:
  ``` Clone the repo and open the solution file in Visual Studio```
