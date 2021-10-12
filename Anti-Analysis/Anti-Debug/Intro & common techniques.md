# _Anti-Debug Overview

_There are a lot of techniques that frustrate the Malware Analysis, some tricks maked by malware writers or used by these, tries to avoid that their malware may be analyzed in deep, it can be detected, but normally, thay modify the malware code to change the behaviour and persisting in time, suppossing that the malware can't be reversed, you can't known how the code works, at this article, I will cover the Anti-Debug (Anti-dbg) techiques, tries to disturb you when analyze a malware in a debugger, terminating the execution or causing excepcions, that's only one, but you will fight versus others like Anti-VirtualMachine (Anti-VM, similar to Anti-Sandbox) and Anti-Analysis (These will anoy when we are at the dissasembler), these other techiques will be showed in the future._

Following with Anti-Dbg, exists APIs focused on this, checking if there are a debugger, one of these, IsDebuggerPresent(), a simple method to enforce, but, simple to detect, when we found this API, we know where we need put a BreakPoint, and therefore, bypass this, I will do tests with some techniques, but, most of Anti-Dbg APIs, are:

> - IsDebuggerPresent()
> - CheckRemoteDebuggerPresent()
> - NtQueryInformationProcess()
> - OutPutDebugString() + GetLastError()

To understand, how this APIs and techiques tricks works, is necessary understand certainly OS parts and some specific Processes structures, first of all, how the TEB (Thread Environment Block) structure is implemented and PEB (Process Environment Block), a lot of the main Anti-Dbg techiques are based on APIs and PEB.

# _TEB & PEB

Both structures, are Windows structures, in TEB case (Sometimes, you will see TEB in TIB, it's the same in practise, but TIB is an older structure that no represents Windows NT) contains some importants elements, at the next image, You will see the contents of TEB, in a img part of [Wikipedia](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block), the difference between FS and GS is only on the bits that you are using, when debugs a 64b Malware the GS:[] apears, but in a 32b Malware... FS:[], si simple, and the usability is the same

![100000000000048E00000254C8096F2E62D09FD0](https://user-images.githubusercontent.com/91592110/136948645-7932d088-f478-464c-9ee2-25dc24aa8b1b.png)

First of all, one important thing is the FS:[0], represents SEH (Structured Exception Handler) normally used by Malware to make exceptions and trap/break the debugging. This functionality is simple, tries to load the FS:0 and create an exception to throw you out of the debugger, one example of this is doing an imposible division like 0/0, to bypass this, we only need to avoid this impossible operation. The techniques using SEH are similar but you can see a lot of these, but if you see a xor eax, eax and next doing an operation with this register, you should change the value of eax, to avoid the exception and this SEH never appears

![1000000000000371000000416DAC8F931CCE44AB](https://user-images.githubusercontent.com/91592110/136948723-ee28dbfb-b6a2-41be-8340-58746d0fc882.png)

Later, the FS:30 that points to PEB structure, this is very important because usually you will see some bytes loaded after the FS:30 to point in PEB structure

![10000000000002A10000001E51E716082394124B](https://user-images.githubusercontent.com/91592110/136948751-d7d4e6b1-577e-4704-b60c-6ad80397c236.png)

Into PEB, we will found other structure, in which, we will see a couple of importants like Being Debugged and ProcessHeap

![10000000000001F30000016DCB7E306FB49FD27C](https://user-images.githubusercontent.com/91592110/136948785-f2459eb9-c61b-4b4e-98f0-2f4146cd858a.png)

Now, we know how the structures are connected, and what's inside, a lot of Anti-Debug techniques will be catched easy, others exists as controlling the time, Heap memory, windows and processes.

As an outline, we have explained this:

```
.
├── TEB/TIB Structure (FS:0 - SEH, FS:30 - PEB)
|     ├─ PEB Structure (FS:30)
|         ├─ Into PEB importants as BeingDebugged or ProcessHeap
 ```
 
 # _Anti-Dbg Techniques
 
 As I explained the structures that will be important to avoid the debugging, we need to know how to do the bypass to these techniques,sometimes, these techniques, will be hard to detect or will occur when you are looking for an API or a Byte and you will be kicked out of the debugger and your analysis will be interrupted, I recommend to take BreakPoints if you don't know what a CALL will do or search previously these 

To start, I will explain two of basic, IsDebuggerPresent and BeingDebugged, based on APIs and PEB structure, later, Heap Flags, techniques based on Times, processes and windows

### ¯_API:IsDebuggerPresent

As I said, in this case, is easy to detect, obviously if you see the Imports, may be called in Runtime, but normally you will see [IsDebuggerPresent](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent) at Kernel32.dll on Imports

![beingdebugged](https://user-images.githubusercontent.com/91592110/136956167-1e891699-94d0-4fdb-af29-581c981c906d.png)

Regarding its functionality, is simple, is a function in which checks if we have a Debugger running, to do that, will return a value or another depending if the process it's being debugged or not. When the value it's NOT 0, the function undrestand a TRUE (Process in debugger), otherwise will be FALSE, supossing that the Debugger detects a 0, it's NOT detecting a debugger running, but if detects a 1 (Or other value not 0), will be break the execution, an example of this technique is the next code:

![100000000000020D0000003B2BF9F19520DAF7B0](https://user-images.githubusercontent.com/91592110/136956233-28d2df50-baf4-49e9-8b0e-aadc7b97fe0d.png)

![1000000000000087000000689AD11A676E717385](https://user-images.githubusercontent.com/91592110/136956261-5b534e12-3083-4bf3-adf1-315b84d1a5b0.png)

Later the execution of IsDebuggerPresent, will do a test eax, eax, as you know, later to the call, the return will be stored on EAX, and if we are debugging the value of EAX will be different to 0, as you can see, we are debugging because we have a 1 in EAX after the call, when we run the next test, the previous jne will break the debugger.

#### ¯_Bypass

To avoid being hunted, the best way to skip this techniques is to modify values, that's important because we need to prevent affect the normal flow of the program, at this case, after the CALL, the TEST wish a non 0 to detect us... As you can imagine, change this value, is the best option, now, we change EAX 1 by 0, and the TEST will be the opossite and this technique it's avoided

![1000000000000104000000B84E83B93F4DBFACF4](https://user-images.githubusercontent.com/91592110/136958628-018bf2c6-5a0c-496d-8c62-7fb8a0ab6993.png)

![1000000000000101000000B15A9880A776499DE7](https://user-images.githubusercontent.com/91592110/136958659-a8fc6eb9-b5c4-4e7e-9a9a-137177a0dfbf.png)

### ¯_Using PEB:BeingDebugged

Next technique is using the PEB structure, there are several that use it, at this case, it looks for BeingDebugged, as you can see, will use the FS:30, pointing to PEB using TEB structure

![10000000000002A10000001E51E716082394124B](https://user-images.githubusercontent.com/91592110/136958832-54c82662-99a7-462b-bfb4-105b124e38c0.png)

![beingdebugged](https://user-images.githubusercontent.com/91592110/136958848-f5122f46-c925-4e9e-acaa-be14693d04db.png)

You can see and example of this technique at this image, you can see how, first of all points to PEB (FS:[30]) and later will do an INC + a CMP, is trying to points on BeingDebugged, if you see the previous image at the PEB structure the BeingDebugged it's at the 0x002 position, at this case, when the eax+2 be 1, the process is being debugged

![100000000000022A000000518E443256BF4958A8](https://user-images.githubusercontent.com/91592110/136958896-3964ab77-d6fc-4f20-ba83-1982b90404d7.png)

![10000000000000580000001A071E724D5C5EF92D](https://user-images.githubusercontent.com/91592110/136958916-6f9c6a55-1ede-45d4-8a83-96156bfcadb8.png)

#### ¯_Bypass

Once we have clear how it works, we need to avoid the detection, to do this, as you imagine... We will change the value on memory, the CMP instruction wants a 1, and we need to change this value to other value, if doesn't match, we will not be detected

### ¯_Using Heap:ProcessHeap

As you know, Heap usually it's used on applications, and off course, Malware, to save bytes while the code it's running to recover that after or exploiting them like in Heap Spraying, well, the next Anti-Debug technique uses one of headers inside of PEB, but, Why uses that? Because the flags that uses to this trick, defines if the Heap would be created by a debugger or not.

To understand it, fist of all, needs to create the access to PEB structure, and, later, to the ProcessHeap, it's at the +18h position at the structure

![10000000000001D4000000E80F09B50961412695](https://user-images.githubusercontent.com/91592110/136974284-67539708-592b-4c50-934a-043b8462cd77.png)

Once access to the [ProcessHeap](https://www.aldeid.com/wiki/PEB-Process-Environment-Block/ProcessHeap), We can see a headers that the Malware will refers later, depending off what OS are you using you will se differents flags, but it doesn't matter, it's the same

![10000000000002350000006CDDBFB25CD2EB22A6](https://user-images.githubusercontent.com/91592110/136974429-12deda14-90db-426f-bd9e-60600f124e34.png)

At the next code, you can see an example of this technique, first, the FS:30 pointing to PEB, later FS:18 pointing to ProcessHeap (Don't forget that ProcessHeap has the 0x018 position on PEB struct) and uses the flag 0x10 referencing the ForceFlag

![10000000000001D20000003BD6474C6F7CD1F9D8](https://user-images.githubusercontent.com/91592110/136974490-363761f7-4b33-4752-8545-d03f133c1303.png)

#### ¯_Bypass

To bypass this, is simple, you can see a cmp at the end that are waiting for a 0, in this case, we have at the ebp-1824 a NON zero value, and we need a 0, now, as you know, we are debugging, so we need to change the value at the cmp and it's bypassed 

There are others that uses this flags Heap (NtGlobalFlag) and behaviour is similar, if you are not skilled on hunting these techniques.You can install some plugins depending on the debugger that you use, in x32dbg/x64dbg have ScyllaHide, in OllyDbg some plugins like Hide Debugger exists and if you are using WindDbg you can run the dbg using -hd to avoid that these flags are made by the debugger

### ¯_Checking the time, hybrid:rdtsc

Another techniques are not based on flags or PEB, others like rdtsc checks the time, You have some similar like GetTickCount or QueryPerformanceCounter which, for example, tries to monitor how long the computer it's on (GetTickCount). Normally, Malware Analysts use Virtual Machines to research Malware, and normally you are switching on and off the machines, this techniques uses that, because it's not common that you run a computer and starts with a DBG...Well nowadays it seems less so rare for me

As you can imagine, these techniques, are used to hunt VM, but to hunt Debuggers too, rdtsc has several uses, for example, run code and count how long it takes to run, as you know, when you are running Malware without a Dbg, the execution will be faster, but if you are step by step on a Debugger, the operation or the code will be slower, that's simple to detect because with rdtsc you can compare execution times of an operation. You can use rdtsc combined with cpuid to hunt CPU cicles using Sleeps. You can see the next image, one example using rdtsc, it's trying to launch similar code and seeing how long it takes to run

![1000000000000133000001C47F6930F23ED6D787](https://user-images.githubusercontent.com/91592110/136974699-240706d5-8d36-47c3-adc6-cd6ead346376.png)

To Anti-VM or Anti-Sandbox is very useful use time checks or control CPU, Threads and so on, I will show it in the future

#### ¯_Bypass

These Time checks, it's not easy to show you a unique bypasss technique, that's because it can be used with different strategic, but if uses a constant to compare an execution time with this constant, change the value, if do a cmp or a test, you know, change values, if uses a conditional jmp, change the flags, always try to avoid to patch if it's not necessary

### ¯_Another Techniques:Window monitor and Processes

Sometimes, we will have another Anti-Dbg that is not based on a internal OS structure o a strategic technique, exists others like window monitoring which check if the window opened is a Debugger (You can imagine that it can be used to another Anti-Analysis) these technique uses common APIs:

> - FindWindow()
> - GetLastError()

The first one is for looking for the dbg window and the second to error codes, if you found the window with the process name X32dbg it will waits to the error code X and the debugger will be detected. 

You can look for processes running, to do that these APIs may be involved:

> - CreateToolHelp32Snapshot()
> - Process32First()
> - Process32Next()

his is simple, it take a "screenshot" from running processes with the first API, and Process32first and next looks for the process, if it's looking for x64dbg.exe, I'm hunted...

![10000000000000AC00000076D769766BFAC160FA](https://user-images.githubusercontent.com/91592110/136975063-0691616b-f7f6-49c6-8f15-eadba99ef81c.png)

#### ¯_Bypass

To bypass this, most easy trick is to find the name of process that the Anti-Debug technique is looking for and change it, an example could be, if you see these API pushing at  the Stack a string x32dbg.exe, stay alert and when it compares the string with any process name changes any to another string and you will be free to debug the Malware

We could find another techniques based on dbg interrupts (Using Int3 caution with 0xCC), exceptions (SEH), create exceptions or uses these techniques it's really useful because you can frustrate the analysis, if you want to avoid these techniques you can fill with NOPs the unwanted code too

# ¯_Summary

To make it easier to remember all of tricks I think that a little scheme will help...

![scheme](https://user-images.githubusercontent.com/91592110/136975366-f5887ea0-546e-486b-a95a-c54a08f8b9eb.png)

As you see, there are various of Anti-Dbg techniques, there are many more, I try to agrupate it in families, but if you know how the tricks works you will know how bypass it. Anyway, you will found a lot of tools focused on Anti-Analysis detection tricks, that's a good weapon to be forewarned, not always will have a lot of time to analyze or bypass all the techniques on Malware, you can take a look on [ShowStopper](https://github.com/CheckPointSW/showstopper) when needs to be faster on your analysis.

> :t-rex: [vc0=Rexor](https://github.com/vc0RExor)  :detective:
