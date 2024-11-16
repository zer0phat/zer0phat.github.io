---
layout: post
title: "ModuleOverride"
categories: injection technique
author:
- zer0Phat
---

<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:site" content="@zer0phat" />
<meta name="twitter:title" content="ModuleOverride" />
<meta name="twitter:image" content="https://zer0phat.github.io/postimgs/df25746e-c321-4b0b-8937-cc69bd65d990.png" />

<a href="/postimgs/df25746e-c321-4b0b-8937-cc69bd65d990.png"><img align="right" width="350" style="margin-left: 20px" src="/postimgs/df25746e-c321-4b0b-8937-cc69bd65d990.png"></a>

When I write my injectors, one of the details I'm interested in is the manipulation of the target process memory. I have already had fun looking for existing buffer in memory that allow me to store my shellcodes without dealing with the allocation of new ones.
I discussed in this [blog]([https://url.of.the.blog/](https://www.covertswarm.com/post/exploiting-microsoft-windows-11-via-process-no-hollowing)) how I used the PE EntryPoint of a Windows process (and the memory pointed by this) to store and execute payloads.

I decided to keep experimenting with this research and to keep posting about it, but I have teamed up with [@5hid](https://github.com/5hidobu) now, and he will publish the analysis of the injector we will create. That should be fun and pretty interesting.

Last pointless detail, I have split the blog post in to two parts, to try not to be excessively tedious to read. Part 2 will be out (hopfully) in the next few weeks.

So, what is these articles about? The previous technique, covered by the aforementioned article, targets a very important memory area of a process. The PE EntryPoint is the address of the very first instructions executed by the main function of a process. This involves:
1. The process must be suspended to prevent the execution flow beginning before we complete the preparation of the payload in memory;
2. In most of the cases a new process must be started. A Running process may be difficult to suspend;
3. Paranoia... What and how many Windows Events are raised? Can I be detected in seconds? Swapping the main instructions of a main function sounds really noticeable;

ModuleOverride targets the DLL modules' memory space instead of the target PE's main function. It uses the same idea of overwriting an existing region of memory in a target process by calling WriteProcessMemory, but it's built on some other cool concepts:
1. No process should be created;
2. Target shoud not be suspended (entirely);
3. Don't touch the main function;
4. Dll injection;

The execution chain steps of ModuleOverride are quite simple. 
```Open a handle to a target process -> identify the desired DLL -> find a suitable buffer in the DLL memory space -> override the memory with our shellcode -> then trigger the shellcode execution```.
To understand why I decided to target a DLL, a bit of knowledge of the PE structure is required. I really don't want to write about the entire PE structure, the internet is full of that, so I will focus on the header that is important to us: ```IMAGE_OPTIONAL_HEADER```.

## Image Optional Header
This PE header contains several parts of information about the PE itself such as the well-known ```AddressOfEntryPoint```, the size of code, the size of the headers, size of stack, heap and so on.
```cpp
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  ...
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```
What really matters for us is the last entry, ```DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]```, an ```IMAGE_DATA_DIRECTORY``` array with a fixed size of ```IMAGE_NUMBEROF_DIRECTORY_ENTRIES```, always set to ```16```.
```cpp
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```
The positions of the entries in the mentioned array are fixes, like its size, and, according to the Microsot documentation, the first entry contains the relative virtual address (RVA) to the ```EXPORT Table```. Knowing that we are dealing with RVAs it's crucial to calculate the correct address in memory.
The ```EXPORT Table``` is an ```IMAGE_EXPORT_DIRECTORY``` data structure which does contain all the relevant information about the function exported by the target PE. If your target PE is a DLL, this structure is even more important.
```cpp
typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD                 Characteristics;
  DWORD                 TimeDateStamp;
  WORD                  MajorVersion;
  WORD                  MinorVersion;
  DWORD                 Name;
  DWORD                 Base;
  DWORD                 NumberOfFunctions;
  DWORD                 NumberOfNames;
  DWORD                 AddressOfFunctions;     // RVA from base of image
  DWORD                 AddressOfNames;         // RVA from base of image
  DWORD                 AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```
The last three entries are the juicy parts we are looking for. ```AddressOfFunctions``` for example, returns the RVA (DOWRD) of the first exported function, but it can also be treated as a pointer to retrieve the array of all the exported functions RVA. The same can be applied to ```AddressOfNames``` and ```AddressOfNameOrdinals```.

<p align=center><a href="/postimgs/0b3dd5ba-1a79-4479-b573-6cd423c75cd7.png"><img src="/postimgs/0b3dd5ba-1a79-4479-b573-6cd423c75cd7.png" /></a></p>

These three arrays can provide me with the lists of exported functions:
- ```RVAs```
- ```Names```
- ```Ordinals``` - which will be use to correlate names and RVAs.

Maybe all these arrays are required for our end goal, maybe not, but first, <i>why is all of this even interesting?</i>

## Exported Functions In Memory

<p align=center><a href="/postimgs/defa6a17-b24b-42a3-8aa3-5726978207a3.png"><img src="/postimgs/defa6a17-b24b-42a3-8aa3-5726978207a3.png" /></a></p>

You can see the list of the modules (DLLs) loaded by a Notepad.exe process from the image above. Let's select a random DLL from the list, in this case I chose ```uiautomationcode.dll``` loaded at ```0x7FF897060000```. The next dll, ```umpdc.dll``` is loaded at ```0x7FF8C6140000```: keep this in mind.
The first exported function, ```UiaReturnRawElementProvider```, can be found at ```0x7ff8970B16D0```. The last exported one at ```0x7ff89717FA50```. In between those two memory addresses there are all the other exported functions.
So we can say that after the base address of ```uiautomationcode.dll``` and before the one of ```umpdc.dll```, the process stores all the ```uiautomationcode.dll``` exported function calls in memory space of ```0xCE380``` bytes at least.

To me, it sounds like  a huge buffer!

<i>To be fair, I did not check if anything else valuable is stored between the exported functions. But, honestly, we don't really care at this stage.</i> 

This block of memory is located within the ```.text``` segment which has an Execute and read (ER) protection. However, this is not relevent since we can modify this protection if we have opened the handle to the target DLL with enough privileges. If you have already read my previous [article](url), you already know that ```WriteProcessMemory``` is going to manipulate the protection for us. if not, <i>do your homework!</i>

## Parse Loaded Modules
In order to get access to the target DLL's ```IMAGE_OPTIONAL_HEADER``` we must retrive the base address of such PE. To do so we must parse all the modules loaded by the targeted running process and retrive the handle to the base.
There could be more efficient and stealthier methods to parse the loaded DLLs, I may discuss them in another blog post. The easiest method is to take a snapshot of the target process' memory and then iterate through the snapshotted modules until the desired DLL is found.

```cpp
HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
HMODULE hMod = NULL;

if (hSnap && hSnap != INVALID_HANDLE_VALUE) {
 MODULEENTRY32 currMod = { 0 };
 currMod.dwSize = sizeof(MODULEENTRY32);

 if (Module32First(hSnap, &currMod)) {
  do {
      /* do whatever you like */
  } while (Module32Next(hSnap, &currMod));
 }
```

```CreateToolhelp32Snapshot``` is used to take a snapshot of a target process (identified with PID ```dwPid```). This function call takes another input, a flag which defines the type of the snapshot.. In this case we are interested in getting the modules so we use ```TH32CS_SNAPMODULE```.
Each ```MODULEENTRY32``` in the snapshot is linked to the one that follows. Thas why we use ```Module32Next``` to advance through the loop.

```cpp
typedef struct MODULEENTRY32 {
  DWORD   dwSize;
  DWORD   th32ModuleID;
  DWORD   th32ProcessID;
  DWORD   GlblcntUsage;
  DWORD   ProccntUsage;
  BYTE    *modBaseAddr;
  DWORD   modBaseSize;
  HMODULE hModule;
  char    szModule[MAX_MODULE_NAME32 + 1];
  char    szExePath[MAX_PATH];
} MODULEENTRY32;
```

```hModule``` contains the handle we are interested in. ```szModule``` holds the name of the module (either a DLL or the EXE) and we will use this parameter to select our desired target.
Once identified. the handle to the DLL can be casted to ```PIMAGE_DOS_HEADER``` (a pointer to ```IMAGE_DOS_HEADER```) and the PE parse can begin.

## Food For Thought
As I said, using ```CreateToolhelp32Snapshot``` and then parse the retrived information to get the module's base address implies taking a snapshot of the target process' memory. Is this right? Taking a look around the internet I found a few discussions about what ```CreateToolhelp32Snapshot``` does under the hood.
The function call seems to follow these steps:
- Open an handle to the target process.
- Call ReadProcessMemory to get the desired information (specified by the ```dwFlags``` passed as an argument) out of the process' ```PEB (Process Environment Block)```.
- Return a handle to such information.

Knowing that it does not effectively take a snapshot, I may want to reproduce the same steps taken by ```CreateToolhelp32Snapshot``` and get the handle to the module by myself. Maybe in assembly<i> ...doesn't it sounds like peb walk?</i>

## In the Next Episode
I think we have all the pieces to start building this dropper but, since I don't want to add too much information and overcomplicate this blog, I will stop here. In Part 2 I will cover the strategy aspects involved in ModuleOverride, how to retrieve the handle to the module in asm, the memory overryde and a few examples on how to trigger the shellcode execution in a safe (and a less safe) way.
