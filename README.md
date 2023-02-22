# MemFiles
### DISCLAIMER: 
#### This project is complex and failure to understand how it works and adequately test it can result in you crashing Beacons and losing access!  
#### I highly encourage you to read all of the documentation up until the "Technical Details, Design Considerations, and Commentary" section!

## Introduction
MemFiles is a toolkit for CobaltStrike that enables Operators to write files produced by the Beacon process into memory, rather than writing them to disk on the target system. It has been successfully tested on Windows 7, 10, and 11; corresponding server versions should work without issue. MemFiles is restricted to x64 Beacons.

It accomplishes this by hooking several different NtAPI's within NTDLL.dll and redirecting calls to those API's to functions that have been injected into the Beacon process memory space.  

**MemFiles assumes a clean/unhooked copy of NTDLL in the Beacon process. No guarantees are made about the viability of MemFiles in a Beacon process where EDR hooks are still in place. Repair/refresh NTDLL before using MemFiles!**

A "special", non-existent directory is defined within the MemFiles toolkit; any files that are written to this special directory will be captured by MemFiles and written into memory where they can then be downloaded to the Teamserver.

MemFiles is compatible with most (not all) tools that run within the Beacon process and that can be instructed to write their output to a specific directory.

This includes:  
-BOF's  
-.NET assemblies ran inline using something like [inline-executeAssembly](https://github.com/anthemtotheego/InlineExecute-Assembly)  
-PE's ran inline using something like [Inline-Execute-PE](https://github.com/Octoberfest7/Inline-Execute-PE)  

All of these are compatible because they run inside the Beacon process, where the relevant NtAPI's have been hooked.

MemFiles does NOT work with things like:  
-execute-assembly  
-shell <program>  
-run <program>  

None of these are compatible because they all spawn other processes whose NtAPI's have NOT been hooked.

MemFiles has successfully been tested with tools like Rubeus, SharpHound, Procdump, and Powershell when they are ran within the Beacon process.  

![](MemFiles_Demo.gif)

## Setup
Clone the repository and optionally alter the hookdir variable that is defined at line 64 in both /PIC/Source/NtCreateFile.c and /PIC/Source/NtOpenFile.c. This variable is the "special" directory that signals to MemFiles it should intercept the file being created. The hookdir variable is set to "redteam" by default. Ensure this variable is not a real directory on the target system, and that it is the same in both files! 

![image](https://user-images.githubusercontent.com/91164728/220270404-1400c099-8589-469d-9891-1010aba3c29b.png)

Run 'make all' to compile both the necessary BOF's and the PIC functions.  

Load MemFiles.cna into the CobaltStrike Client. Ensure the directory that CobaltStrike is running from is writable by your user; MemFiles creates a text file there (memfiles.txt) in order to ensure availability of the data required by MemFiles to function.

MemFiles can be configured to install in each new Beacon that calls into the Teamserver; this is accomplished by using the MemFiles->Config menu item. By default, MemFiles does NOT auto-install in new Beacons.  **Note that this is a global setting; if two Clients are connected to the Teamserver and both have MemFiles.cna loaded, if Client A toggles the "Install on beacon initial" setting, the change will also take effect for Client B!**

![image](https://user-images.githubusercontent.com/91164728/220257258-46fc8e87-1023-486d-8811-6e9155252e6e.png)

## Commands
MemFiles comprises of 4 target-facing commands which run BOF's and 1 internal command that manipulates the project data structure. 

Target-facing:  
1. meminit  
2. memlist  
3. memfetch  
4. memclean  

Internal data structure:  
1. memtable  

### meminit
meminit is responsible for installing MemFiles in the Beacon process.  

The list of NtAPI's hooked by MemFiles is as follows:

1. NtCreateFile  
2. NtWriteFile  
3. NtClose  
4. NtQueryVolumeInformationFile  
5. NtQueryInformationFile  
6. NtSetInformationFile  
7. NtOpenFile  
8. NtReadFile  
9. NtFlushBuffersFile

meminit performs the following major actions:

1. Sends a position independent replacement function for each hooked NtAPI to Beacon  
2. Creates a structure in Beacon memory to hold various values required by MemFiles throughout it's lifecycle  
3. Patches the address of this structure into each one of the PIC replacement functions  
4. Allocates memory and injects each PIC replacement function into Beacon process memory  
5. Creates a trampoline for each hooked NtAPI  
6. Hooks each NtAPI listed by overwriting some/all of the bytes, redirecting execution to the PIC replacement function.  

### memlist
memlist is used to display all files currently stored in memory by MemFiles for a given Beacon.  
![image](https://user-images.githubusercontent.com/91164728/220259958-4017f11f-a2bb-4fb1-8d95-20cc904e6590.png)  
Several fields are displayed, the most relevant and of interest to the user being the name of the file and the length of the data stored.

### memfetch
memfetch is used to actually retrieve files stored in memory by MemFiles for a given Beacon.

By default, memfetch will retrieve any and all files stored by MemFiles whose "handle" has been closed. This design choice was made to avoid any issues relating to trying to download a file that a program/application has not finished writing to.  

This means that if a program/application fails to close the handle it opens to the file, the file will not be downloaded by memfetch.  
This can be mitigated by using the "force" argument with memfetch, i.e. 'memfetch force' in order to retrieve all files from memory regardless of the status of it's handle.

Files that memfetch retrieves from memory are sent back to the Teamserver as a download and can be synched from the Teamserver to the Client via the Downloads tab in CobaltStrike. 

Once a file has been downloaded by the Teamserver, it is wiped from memory in the Beacon process and its' entry as shown via memlist removed.

### memclean
memclean is responsible for cleaning up and removing MemFiles from a Beacon process.

The standard use case for MemFiles involves installing it and leaving it installed for the duration of the Beacon's lifetime; however should one want to use MemFiles in conjunction with a tool to capture and retrieve file output, and then uninstall MemFiles so that it's artifacts aren't in memory, memclean can be used to revert the Beacon process to it's original state before meminit was ran.

This involves:

1. Unhooking each hooked NtAPI  
2. Zeroing out and freeing each created trampoline  
3. Zeroing out and freeing each injected PIC replacement function  
4. Zeroing out and freeing the MemFiles struct

Note that before memclean performs these actions, it will forcefully download any files stored in memory by MemFiles. If one intends to use MemFiles with a single tool and then remove it, they can skip using memfetch and just use memclean to both retrieve the files AND remove MemFiles from the Beacon process in one shot.

### memtable
memtable is used to display and track information regarding Beacon's in which MemFiles is currently installed. It also displayed global configuration information.

Each CobaltStrike Client has their own memtable; MemFiles goes to great lengths to ensure the synchronicity of its data between all connected CobaltStrike Clients so that MemFiles may be used by all Operators in all Beacons. For more on this, see "Design Considerations and Commentary".  

![image](https://user-images.githubusercontent.com/91164728/220262399-f0b470c1-2e62-4841-ae73-8a302b495e53.png)

## Usage
Initialize MemFiles in a Beacon by using the meminit command. This can be configured to happen automatically by toggling the option in the MemFiles->Config menu. 

![image](https://user-images.githubusercontent.com/91164728/220262963-c90f9477-444e-4c72-918a-4d7710e6dcb2.png)

With MemFiles initialized, you can now use your favorite tools to write files into memory! How you do so will depend on the specific tool; some allow you to specify a directory to output multiple files into, while others allow an absolute path to be specified for a singular file that is created by the tool.  A few examples can be seen below:

#### SharpHound: ####

Here we specify that SharpHound should output all produced files to the c:\redteam\ directory (our special MemFiles directory) and that it should not zip the files; MemFiles does not support programs reading files from memory, only writing them, so the zip functionality in SharpHound does not work.  

![image](https://user-images.githubusercontent.com/91164728/220265316-bc319778-0ba2-40d6-9e8c-fee9480e0824.png)

#### Rubeus: ####  

The "dump" command is used with Rubeus and we instruct it to send all console output to a file (located in our special directory)

![image](https://user-images.githubusercontent.com/91164728/220265384-b24106e4-4929-4ecb-a5af-f95c6159214d.png)

#### Powershell: ####

In this example, Inline-Execute-PE is used to load powershell.exe into the Beacon process and run 'Get-ADUser' to retrieve a list of domain users.  Using a pipe and 'out-file', the data can be written into memory and then retrieved.

![image](https://user-images.githubusercontent.com/91164728/220268247-f47b2cfd-1a05-4502-b2c3-57a8a8ac2c67.png)

When you want to retrieve your files, run memfetch:

![image](https://user-images.githubusercontent.com/91164728/220268707-efc93fcb-efa8-421b-8565-dc5e683d8076.png)

When you are done with MemFiles and/or don't want to leave it installed in a Beacon process, run memclean:

![image](https://user-images.githubusercontent.com/91164728/220268866-4f215ee8-3daa-4f3d-a938-5b8c619894ba.png)

Note that in the above example, there was a file that had not been downloaded yet; memclean downloads this file and wipes it from memory before uninstalling MemFiles.

Query the status and configuration of MemFiles using memtable. During long operations, clear entries from dead/old beacons from memtable to avoid clutter.

![image](https://user-images.githubusercontent.com/91164728/220269319-87259689-06b0-4473-8fae-5ed652328570.png)

## Capabilities and Limitations
As emphasized in the Introduction, MemFiles requires a clean copy of NTDLL in the Beacon process in order to function. This is necessary because it reads the original bytes in the NtFunction and copies certain ones to the trampoline, which is later used to complete normal calls to the NtFunction that MemFiles should not interfere with. This subject is gone into more detail in the "Technical Details, Design Considerations, and Commentary" section.

MemFiles makes an initial allocation of 1048576 bytes for each file; as data is written to memory, it can and will expand this allocation as needed to hold larger files.

The filename stored in the MemFiles struct is parsed out of an argument that is passed to the replacement NtCreateFile function.  MemFiles does this is a fairly simplistic fashion, by locating the "special" directory in the file path argument, seeking to the end of it, and then incrementing the pointer by 1 to account for the '\\' character that separates the "special" directory and the filename.  For example, in the path 'C:\users\tom\redteam\myfile.txt', MemFiles locates 'redteam', accounts for the backslash character, and selects 'myfile.txt' as the filename.

MemFiles doesn't care about any preceding directories in the file path; 'C:\redteam\myfile.txt' and 'c:\users\tom\appdata\local\redteam\myfile.txt' are equally valid paths as far as MemFiles is concerned. 

Given how MemFiles parses filenames out of file paths, it should be noted that MemFiles does not support the creation of subdirectories; this means that MemFiles will not function properly with tools that, for example, try and create c:\redteam\mynewdir\file1.txt, c:\redteam\mynewdir\file2.txt, c:\redteam\mysecondir\file3.txt, etc. 

The NtAPI's hooked by MemFiles have been identified as ones used by various programs for I/O operations. As previously mentioned, tools/capabilities successfully tested with MemFiles/this set of hooked NtAPI's are: SharpHound, Rubeus, Powershell, Procdump, BOF's, generic C programs that perform file write operations, and CobaltStrike's bupload_raw command (which allows the Operator to specify the remote file location). There are certainly other tools out there that will function with MemFiles out of the box; others will be incompatible.

At first glance, the Windows file creation process looks to be straight forward: NtCreateFile->NtWriteFile->NtClose.  Quickly after digging into this project I found that there were a number of other API's involved, and for extra fun the other API's involved differ between programs. Some programs as part of their I/O process call the Win32 API SetFilePointerEx, which in turn calls the NtAPI NtSetInformationFile. Others, like .NET programs including SharpHound, end up calling NtFlushBuffersFile. 

The lack of a single common chain of API calls to create and write files opens room for incompatibility depending on the tool that MemFiles is used with. A program might call another NtAPI that MemFiles hasn't hooked, passing the fake handle created by MemFiles in the replacement NtCreateFile function and resulting in a "Invalid Handle" error which halts execution. Other programs perform more complex actions that MemFiles does not adequately spoof/replace. One such incompatibility already identified is ADExplorer.exe.

ADExplorer.exe is a signed Microsoft binary used for active directory enumeration. During runtime, ADExplorer writes data to the specified output file and then later goes back and references it before ultimately writing the final output to the file at the end of execution. Because it uses the output file as a cache of sorts, it has to be able to read the data that it has already written to the file, and there is a very low chance it does so in any kind of simple, predictable fashion.  

MemFiles does not currently support in-memory files being read by programs or applications, but this should be possible with more fleshing out of the custom NtReadFile function and some additional variables/data tracking added to the MemFiles struct.

ADExplorer presents another challenge in the size of the files it produces. In large enterprise environments the output file can exceed 1GB; while MemFiles should programmatically be able to handle this, it certainly isn't intended for such use cases.

### Incompatible Tools
Undoubtedly the community will discover tools with which MemFiles does not function properly; I encourage you to open an issue detailing the incompatible program/tool and the circumstances in which you ran it, i.e. it's a BOF, via inline-executeAssembly, Inline-Execute-PE, etc. so that I can see if I can't expand MemFiles and get it working.

## IOC's and AV/EDR
IOC's associated with MemFiles include but are not limited to:

Allocating memory using VirtualAlloc  
Writing data using WriteProcessMemory  
Changing memory protections on allocated memory between RW and RX  
Overwriting memory within NTDLL.dll  

### AV/EDR
MemFiles was not developed against or tested against a proper EDR; Microsoft Defender is what was available. That being said, I'd hazard to say that whatever tool/program Beacon is running to produce a file is more likely to be alerted on than MemFiles capturing or storing that file in memory. The overwriting of memory in NTDLL/hooking the NtAPI's strikes me as something that some products might take issue with, but I don't have any evidence to corroborate this. For calls to hooked NtFunctions that do not concern files that are/should be captured by MemFiles, the syscall is still issued from within the NTDLL.dll address space, as security products do detect and alert on syscalls made from outside this area.

It should be noted that files stored in-memory by MemFiles are NOT encoded or encrypted; this feature could be added if a real use case/instance where AV/EDR is alerting on a produced file in-memory is identified. 

## Technical Details, Design Considerations, and Commentary
I was first introduced to the concept of an in-memory file system by a conference talk several months ago at KFiveFour's Tradecraftcon, where a speaker (@DexterGerig) demonstrated a POC that created an in-memory file system using a Client-server model.  Half of my envisioned functionality of such a project was covered by my last major release, Inline-Execute-PE.  The other half, the idea of being able to capture files produced by tooling and store them in memory rather than on disk, wasn't fulfilled by that project and remained a highly desirable capability for obvious reasons. 

MemFiles was an incredibly challenging undertaking for me as prior to this project I had spent very little time in a debugger, had no understanding of assembly, and didn't understand API hooking.  I encountered several 10-20 hour long roadblocks during this project which with persistence I was thankfully able to move past.  While probably not the most efficient way to do so, I gained a lot of familiarity with debuggers and greater understanding of how computers work under the hood when it comes to assembly, registers, the stack, and calling conventions. 

What follows is a technical deep dive on some of the more important technical details and design considerations that have gone into MemFiles.

### Files in Windows, and How MemFiles Works
File creation on Windows starts with NtCreateFile, to which the path of the desired file is given and in return Windows creates a file at that location and provides a handle to it. The returned handle is used in all subsequent calls involving the file, for example to NtWriteFile and NtClose.  

In thinking about how to separate calls to all of these API's between ones we want to intercept and tamper with and those we want to leave alone, I landed on looking for a keyword in the NtCreateFile call. This was accomplished by specifying a unique, non-existent directory as part of the file path in the NtCreateFile call. When our hook redirects execution to the replacement NtCreateFile function, the file path passed as an argument to NtCreateFile is examined for the presence of that unique "keyword"; if it locates it, MemFiles knows that this NtCreateFile call relates to a file that should be placed in memory instead of on disk.  When this occurs MemFiles initializes several variables and allocates an initial 1MB of memory for use by the file, but most importantly it associates a fake handle with the filename specified in the MemFiles struct, and returns this fake handle to the caller.

For all of the other NtAPI's hooked by MemFiles, the corresponding replacement NtFunction's look at the handle passed in as an argument and see if it exists in the MemFiles struct; if the handle does exist (the fake handles produced by MemFiles are sufficiently fake that they shouldn't ever have crossover with a real one) in the MemFiles struct, MemFiles identifies this call as one concerning an in-memory file and acts accordingly.

### Hooking theory and replacement functions
In order to write files into memory that were destined for disk, MemFiles needs to intercept calls to certain API's which are made by programs when they try to create a file. API Hooking has been around for a very long time, and is actively used by many EDR products as a core part of their functionality; calls to certain API's are redirected to the EDR address space, where analysis is done on the API call and the variables passed into it.  If the EDR determines the call is malicious, part of an attack tool or kill chain for example, it will prevent the call from completing and raise an alert. If the EDR decides that the call is benign, it will patch execution back to where it was redirected from and allow the API call to complete as originally intended. A simplistic analogy can be found in saying that you mail a letter to a friend, but before your friend receives it a third party opens it, reads it, and then decides if there is something in the letter that is illegal in which case your friend never receives the letter and the police are alerted. 

MemFiles follows the same theory, without the alerts (or theoretical police involvement). API hooking is typically implemented at the lowest level possible in userland; the NtFunctions within NTDLL.dll. Lets take a look at NtCreateFile, before any hooking has taken place:

<img width="745" alt="image" src="https://user-images.githubusercontent.com/91164728/220404671-fe937872-3db8-41ff-86ad-623a4de72616.png">  

All NtFunctions are identical, with the exception of the syscall number, which is 55 in this example.  The syscall number changes between NtFunctions, and it should also be noted that this number can change between Windows versions; the syscall number for NtCreateFile on this OS (Windows 11) is 55, however it might be different on Windows 10 (and certainly on Windows 7). 

It is worth noting the TEST and JNE instructions. These exist to determine whether the NtFunction should use the normal syscall instruction, or the legacy INT 2E instruction. I will quote from klezvirus's post [SysWhispers is dead, long live SysWhispers!](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/):

>Now the interesting part, the function checks if SharedUserData[0x308] (BYTE PTR DS:[7FFE0308]) is set to 1. SharedUserData is a symbol referring to the Kernel mode structure KUSER_SHARED_DATA.
>
>The KUSER_SHARED_DATA structure defines a fixed (or pre-defined) memory space used to share information with user-mode software. This, of course, was done for making certain global system information ready to be consumed by user-land code without the overhead to switch every time between user and kernel-mode execution.
>
>The value at index 0x308 represents the syscall instruction, which is supported in all Windows versions from 1511. As you might imagine, in all versions of Windows before 1511, the standard way to execute a syscall was by calling the interrupt int 2Eh.
>
>...
>
>If you’re asking yourself why this int 2Eh is still there, even if Windows is now far above version 1511, it’s because this instruction is still used. Indeed, when HVCI (Hypervisor-protected Code Integrity) is enabled, SharedUserData[0x308] is set to 0, and the int 2Eh is used instead of the syscall instruction. This is mostly done for performance reasons, due to how the Ring3 to Ring0 switch is operated using one or the other instruction.
>

I asked for further clarification on this topic on twitter, to which @yarden_shafir said the following:  

![image](https://user-images.githubusercontent.com/91164728/220477066-be7f0c4d-15e8-4a02-b2b9-350968bca20c.png)  

Long story short, every instruction in the NtFunction might be needed at some point (with maybe the exception of the multi-byte NOP found at the end that doesn't appear to be reachable), and if we overwrite instructions in the NtFunction we need to ensure that we save them and execute them at some point before we make the final syscall (or INT 2E as the case may be).

It is worth noting that prior to making the syscall, the syscall number is moved into RAX (shown as EAX in the screenshot). Because we don't see RAX pushed to the stack prior to this, I (perhaps naively) assumed that the value contained in RAX prior to the syscall number being moved there is not important or required later after the syscall has been issued. This is good news, as it means we can use the RAX register freely as long as we ensure it contains the syscall number before the syscall is issued.

In order to redirect execution to our custom code/replacement NtFunction, we will overwrite part of the original NtAPI, moving the address of our replacement NtFunction into RAX and then using a JMP instruction to go to that code:
  
<img width="741" alt="image" src="https://user-images.githubusercontent.com/91164728/220422651-a81e214c-f989-490a-9690-9a56d7982c16.png">  

12 byte are required for the MOV and JMP instructions; because we are mangling other instructions by overwriting the first 12 bytes of the NtAPI, those instructions have been replaced by NOP's in order to maintain the proper spacing and alignment of the NtAPI.
  
When the program now calls NtCreateFile, it will jump execution to our replacement NtFunction.

### Custom Code and Replacement NtFunctions
MemFiles deviates from how EDR's perform hooking in regards to where the replacement functions that hooked API's are redirected to reside.  Many EDR's will load their own DLL into a process.  Hooked API's are redirected to the address space of this loaded DLL where analysis can take place. Being that the entire point of this project was to avoid dropping things to disk, placing a DLL on disk and having our Beacon process load it in order to have access to our replacement NtFunctions seemed like a poor avenue. There is a [several years old POC](https://github.com/fancycode/MemoryModule) available that allows the loading of DLL's from memory, which is a viable strategy for our needs, but the project isn't maintained and there appear to be several issues with it. Additionally it is 1200 lines of code and would be a beast to convert to BOF format. 

As a quick aside, our replacement NtFunctions cannot reside in a BOF; CobaltStrike loads, runs, and then wipes BOF's from the process memory when they are done.  Being that we are in need of a persistent function(s) in memory that can called whenever the process calls one of the hooked NtAPI's, BOF's won't work.
  
The answer I came to was position independent code (PIC). As the name implies, in contrast to normal executables that require they be loaded in a certain place/with parts of it in certain relation to others, PIC can be placed and ran anywhere in memory.  This opens the door to writing our replacement NtFunctions as PIC executables, injecting them into the Beacon process, and having our hooks redirect execution to them when calls to our hooked NTAPI's are made.
  
The template for these PIC NtFunctions comes from Cracked5pider's [ShellcodeTemplate](https://github.com/Cracked5pider/ShellcodeTemplate) project.

One notable deviation from the base project is that the base project is designed around creating a full PIC exe; that is to say it has ASM included to save the stack pointer, create space on the stack, call the designated replacement NtFunction contained within the exe, and then restore the stack pointer once that function has returned. The call instruction made by the PIC exe presents a problem, as doing so pushes the return address of where the call was made (in the PIC exe ASM) onto the stack which will lead to the ret instruction encountered later returning execution back into the PIC exe, rather than to the caller of the original NtAPI. 
  
To mitigate this, the ASM file in the ShellcodeTemplate project was edited to remove the ASM related to setting up the stack, calling the function, and then restoring the stack pointer after the function has finished execution. The result is that the hook placed in the NtAPI now jumps execution directly into the replacement NtFunction, with the stack and registers set up as they were when the original NtAPI was called by the program (with the exception of RAX which is used for our JMP).

Original ShellcodeTemplate ASM:  
<img width="296" alt="image" src="https://user-images.githubusercontent.com/91164728/220423560-13df4b5b-f18f-4bb8-802d-b2d9c6dbebc3.png">  

MemFiles ASM:  
![image](https://user-images.githubusercontent.com/91164728/220471631-798bcb2d-22af-45cf-b6bc-021e82ed1a0d.png)

Each hooked NtAPI has their own PIC NtFunction that contains the requisite logic to either:
  
  A. Perform MemFiles specific actions such as creating a fake handle, writing data into memory, altering variables in the MemFiles struct, etc  
  or  
  B. Direct execution to a trampoline which will get the API call back on track and patch it back into NTDLL where the syscall can be made
  
Some of the replacement NtFunctions are more complex than others; when a call to a hooked NtAPI is one that concerns MemFiles, some, like NtCreateFile and NtQueryVolumeInformationFile, modify variables that were passed in as arguments to the NtAPI in accordance with MSDN documentation, results of testing, and some guessing/common sense. Others, like NtClose and NtReadFile, simply return STATUS_SUCCESS to the original caller in order to avoid the inevitable "Invalid Handle" error that would otherwise arise from passing in a fake handle created by MemFiles.  

When a call to a hooked NtAPI does NOT concern MemFiles, we need to direct execution to a trampoline in order to get things back on track:

![image](https://user-images.githubusercontent.com/91164728/220472162-7b6e9a88-f20a-495a-b16d-e4ded0647ef4.png)

### Trampolines
The trampoline is responsible for executing any/all instructions that were not executed in the original NtAPI due to that API having been hooked; this includes any instructions partially or totally overwritten by the original hook.  Hooking API's can quickly lead to issues where we don't have enough space to perform all of the instructions that we need to.  Trampolines can help alleviate this problem as well, as we can perform any number of actions to set up our registers and/or stack before we jump back to the original NtAPI. The NtCreateFile trampoline can be seen below:  

![image](https://user-images.githubusercontent.com/91164728/220473089-b6dd40b9-668b-4e5a-be64-a0b0e1c34fd4.png)  

Most obviously, the three instructions overwritten by our initial hook can be seen as the first three instructions in the trampoline:  

MOV R10, RCX  
MOV EAX, 55  
TEST BYTE PTR DS:[7FFE0308], 1  

As mentioned earlier, the big requirement in all of this manipulation is that the syscall number (55 in the above example) reside in RAX(EAX) prior to issuing the syscall. We have an issue however in that we still need to use a JMP instruction to direct execution back to the original NtAPI.  While there may be another register that isn't holding important information and could be leveraged to do so, I didn't find a consistently safe option given the number of NtAPI's that we are hooking, each of which might be using the registers differently. The safe option is to continue to use RAX; we can do so by pushing the syscall number stored in RAX onto the stack.  We can then move the address wish to jump back to in the original NtAPI into RAX and use a JMP instruction to arrive back in NTDLL:

![image](https://user-images.githubusercontent.com/91164728/220476075-f7b64a9e-92d4-43fc-9788-646139da1870.png)  

Included in the hook that is installed in the NtAPI is a POP RAX instruction, and this is where we jump to using our trampoline. Executing this instruction restores the syscall number to RAX from the top of the stack and sets us up to issue the syscall.  Note that the JNE instruction from the original, unhooked NtAPI is still here; the corresponding TEST instruction, which sets the ZF flag and dictates whether or not a JNE is taken (which would jump us over the syscall to the INT 2E), was performed in the trampoline. Arranging things this way lets us both successfully hook the NtAPI and redirect execution to our replacement PIC NtFunction, as well as ensure that we aren't skipping anything or losing any functionality as a result of our hooking.

### A Cart Before the Horse Problem
To briefly summarize what has been covered thus far, when MemFiles is initialized a struct is created in the Beacon process memory that contains important information for the functionality of Memfiles. Information in this struct is continually referenced throughout MemFiles's lifecycle, to include by each one of the replacement PIC NtFunction's as well as by the BOF's that are used to query and fetch files stored in memory by MemFiles. To this end, when the struct is created the memory address the struct resides at is communicated back to the Teamserver:  

![image](https://user-images.githubusercontent.com/91164728/220262963-c90f9477-444e-4c72-918a-4d7710e6dcb2.png)  

After storing this address in memtable, subsequent MemFiles commands (memlist, memfetch, memclean) send this address as an argument to the BOF so that the struct can be located and referenced. But how do the PIC NtFunction's locate the struct?

The glaring issue is that the PIC NtFunction's require the memory address of the MemFiles struct, but they are already compiled by the time the struct is created. An early implementation of MemFiles tackled this problem by splitting the initialization of MemFiles into two separate BOF's. The first created the struct and sent the address back to the Teamserver, which through some Aggressor script magic would parse out the address, insert it into the source code file for each NtFunction, and then recompile them into the final PIC NtFunction. The second BOF would then transmit the finished PIC NtFunctions and do the actual injecting and hooking of the NtAPI's.  

Aside from being ugly and taking extra time, real issues could arise in the situation where multiple beacons are trying to initialize MemFiles at the same time. If Beacon 2 were to call back with it's MemFiles struct address while Beacon 1 is in the process of patching in and recompiling the NtFunction source code files, things could get messy.

The elegant solution to this problem involves performing a binary patch on the PIC NtFunction, wherein the MemFiles struct address is patched into the compiled NtFunction and accessible during runtime. To facilitate this, a placeholder string is written into each NtFunction:

![image](https://user-images.githubusercontent.com/91164728/220484099-792e6eff-e643-4bed-86a1-38ccaeba80bb.png)  

This variable can be seen in the compiled code using a tool like xxd:  

![image](https://user-images.githubusercontent.com/91164728/220484246-ac3d6a74-6908-4ea2-9b47-1179050123a9.png)  

When the meminit command is ran, each of the PIC NtFunctions is sent to Beacon along with the InstallHooks BOF. This BOF is responsible for creating the MemFiles struct; after it has done so, it calls the patchAddr function on each one of the PIC NtFunctions. patchAddr is responsible for locating the string of A's and replacing it with the string representation of the struct address. In effect, using the memory address from the earlier screenshot, the pFileInfoStr variable now looks like:

>char* pFileInfoStr = GET_SYMBOL( "00000178BC106860" );

This string representation can then be transformed into the actual hex value, which is our memory address.  The BOF's accomplish this quite simply using the _strtoi64 API:  

![image](https://user-images.githubusercontent.com/91164728/220485222-be598c82-60bf-4834-8529-2a9a8e1e6ea5.png)

Of course things couldn't possibly be this easy for the PIC NtFunctions.

This brief snippet of assembly shows the end of one of the PIC NtFunctions. Note the JMP RAX instruction, which is the PIC NtFunction calling the trampoline (meaning this is a call MemFiles did NOT spoof/interfere in):

![image](https://user-images.githubusercontent.com/91164728/220485680-e1c436cc-1839-4a01-aa7e-5cdac1c15cf4.png)

For reasons unknown, when I attempted to use _strtoi64 (or any of its cousin API's like stroull or atoll), this JMP RAX instruction became a CALL RAX instruction. I'm sure there is a valid reason for this involving some deep level of "how computers work", but this seemingly insignificant change breaks quite a few things. After spending 15+ hours trying to find a way to transform the string representation of the MemFiles struct address to the actual hex value so I could utilize the values stored within, I came across [this StackOverflow post](https://stackoverflow.com/a/39052987/18776214) in which a commenter provided a custom routine designed for microcontrollers to convert a string to a uint32; thankfully it also worked for a uint64 without modification, and most importantly it preserved the JMP RAX instruction later in the PIC NtFunction without altering it to a CALL. The final snippet:  

![image](https://user-images.githubusercontent.com/91164728/220486708-ab0aa844-c169-4502-9faa-380f77228db3.png)

### Old NtAPI VS New NtAPI
For the sake of simplicity it was not mentioned earlier, but the format of the NtAPI's has changed over the years. Earlier versions, like those used by Windows 7, are much shorter than their modern counterparts, being only 16 bytes long instead of 32:  

![image](https://user-images.githubusercontent.com/91164728/220488170-d53f134c-7dbb-4a04-8fd7-ea6cc497c3e8.png)

This requires changes to how the NtAPI's are hooked by MemFiles as well as how the trampoline is built. In order for MemFiles to identify the version of the NtAPI's it is dealing with, the InstallHooks BOF first resolves the address of the NtAPI in question and then reads 32 bytes from that location. The different format results in the syscall instruction being located in different places between the NtAPI versions; by checking for the presence or absence of the syscall at a certain byte offset, MemFiles is able to determine if it is dealing with the modern or the legacy NtAPI implementation and act accordingly:

![image](https://user-images.githubusercontent.com/91164728/220489454-15f299b3-f3f6-421e-83ca-c05e549c1080.png)

After hooking, the legacy NtCreateFile API looks like this:  

![image](https://user-images.githubusercontent.com/91164728/220488456-efe79a23-a5c2-46bb-b326-863e6e139853.png)

And the trampoline used to set up registers and then jump back to NtCreateFile:

![image](https://user-images.githubusercontent.com/91164728/220488528-83881e2d-12cb-463a-9d77-e289edb9b0e5.png)

Overall the technique is very much the same, but things are a lot tighter and without much wiggle room.  It is worth noting that to make it all fit and function properly, the syscall instruction had to be moved within NtCreateFile; it still resides in the NtCreateFile API memory space within NTDLL, but it has shifted from the 9th and 10th bytes of the API to the 14th and 15th bytes of the API, the multi-byte NOP having been sacrificed in order to cram everything in properly. 

### Finding I/O Related NtAPI's
Some of the API's related to file I/O operations were intuitive and thus easy to identify and hook; others were far more elusive, requiring hours and hours spent in WinDbg and x64dbg stepping through assembly trying to identify what API's were being called. I have to believe there was a more efficient way to accomplish the task, but I was learning as I went.

As a quick extra, I thought I would detail the, what in hindsight should have been very quick, process to identify the NtAPI that was preventing SharpHound from working for 20 hours. Being a .NET program, SharpHound spit out a very ugly call stack all relating to the fact that it had determined that "The handle is invalid". While .NET is a programmer-friendly language, most(all?) functionality gets translated and ultimately passes through the Win32 API (and as a result the NtAPI) where we can observe and hook it just like anything else.

![sharphounderror](https://user-images.githubusercontent.com/91164728/220491193-fe480d12-2c80-4f26-a5b1-11ae1df886eb.JPG)

The "Invalid Handle" error was a dead giveaway that there was an NtAPI used by SharpHound that I wasn't hooking (as opposed to one of my existing PIC NtFunctions not working properly), so I set out to try and figure out what it was. The technique I had used with other tools up to this point was to first set a breakpoint on NtCreateFile and locate the call that concerned my "special" directory. From there I would step through the program (usually several times because I would get lost), and see what functions the program called next. Following this methodology is how I discovered that NtQueryVolumeInformationFile, NtQueryInformationFile, and NtSetInformationFile were called and needed to be hooked.

SharpHound throws some extra curveballs in that it performs many of it's tasks asynchronously. This makes it much more difficult to trace the linear steps that a single file takes through API calls because there are several files going through the process simultaneously.  In addition, I found by stepping through the program after the NtCreateFile call that eventually the thread in which the NtCreateFile call was made terminates; the eventual NtWriteFile calls (and whatever other unknown API calls that are the subject of this search) happen in a different thread, which further confounds the search process.

Having only briefly dealt with .NET I wasn't well versed in parsing call stacks produced by errors, doubly so for those that are made twice as ugly by the use of async. Over the course of the 20 hour problem, in the absence of progress using my earlier strategy, I kept returning to it and slowly but surely made more sense of it. About the third "chunk" from the top as separated by the "--- End of stack trace..." lines, a line can be seen reading "at Sharphound.Writers.JsonDataWriter...". This gave me a relative place to start in the actual SharpHound code, which is open source and available on Github. As the name suggested, the SharpHound function dealt with writing JSON output out to file; I was already aware that my data was writing out to file successfully so this wasn't news. Tracing up the call stack one level, the next relevant line was "at System.IO.Streamwriter.<FlushAsyncInternal>". The System.IO prefix told me this was a .NET inherent, as opposed to a SharpHound specific function. Looking at the very top section of the call stack, the line that jumped out at me was "at System.IO.FileStream.FlushOSBuffer()".  I decided to google FlushOSBuffer and see what I could find. 

Doing so led me to Microsoft's .NET documentation for [filestream.cs](https://referencesource.microsoft.com/#mscorlib/system/io/filestream.cs). There I found the definition for FlushOSBuffer:

![image](https://user-images.githubusercontent.com/91164728/220492482-a77f6bcc-8440-48cf-b750-686e576c9f17.png)

It appears to call a Win32 API, FlushFileBuffers. The definition for Win32Native.FlushFileBuffers can be found by looking at the [Win32Native]() documentation:

![image](https://user-images.githubusercontent.com/91164728/220492711-04d0c8ff-d38c-4457-a880-dcf9aafaf22b.png)

Anyone who has worked in .NET with P/Invoke will recognize the format. I now had a Win32 API that I knew System.IO.Filestream.FlushOSBuffer(), my problem .NET function, calls.  Setting a breakpoint on KERNEL32!FlushFileBuffers and running SharpHound confirmed this, and by stepping through I quickly saw that under the hood FlushFileBuffers calls NtFlushBuffersFile. Hooking this API alleviated the issues SharpHound was having and enabled it to run successfully, writing it's output files to memory.

### Downloading Files from Memory
A critical part of this project is the ability to actually download the files to the CobaltStrike Teamserver once they are in memory. Predictably the normal CobaltStrike download command won't work with a filepath that doesn't really exist. Knowing what I know now, a solution probably lies in fleshing out the replacement PIC NtReadFile code to facilitate the in-memory files being able to be read instead of just written. Not having that knowledge beforehand, being able to actually retrieve the files was a major blocker.

By accident I came accross a [BOF](https://github.com/EspressoCake/DLL-Exports-Extraction-BOF/blob/main/src/main.c) written by EspressoCake that contained a function that jumped out at me: 

![image](https://user-images.githubusercontent.com/91164728/220497585-4c45ce6b-f8f1-421d-8ab8-eaaa2793eae7.png)

Looking through the code it appears to use an undocumented Beacon CALLBACK option:

![image](https://user-images.githubusercontent.com/91164728/220497681-38a70b8b-2b47-4baf-995a-e2ce5e6e118b.png)

The function enables a BOF to initiate the download of a file to the Teamserver **from the target**, as opposed to from the Client. This capability (which I later learned was a combined effort of several other people to include @Cr0Eax, @EthicalChaos, and @anthemtotheego) removed the major blocker that previously existed, as I now had a way to initiate a file transfer from the target system for the in-memory file. Big thanks to all involved for this code snippet which I forsee being useful in the future as well.

### MemFiles Data Structure
A challenging part of this project was ensuring the availability of MemFiles functionality to all CobaltStrike Clients connected to the Team Server. MemFiles's data is stored in structures created by MemFiles.cna, which must be loaded into each Client that wishes to use the tool; as a result, these data structures live within each Client, not on the Team Server. If this data did live in a single central location (TS) it would be trivial to retrieve it from each Client and this whole thing would be a non-issue; were the CobaltStrike Team to formally integrate a capability like MemFiles into CobaltStrike I am positive this is the direction they would go. But being that this is a community add-on, we make do with what we have.

There are a couple different scenarios we have to worry about when it comes to ensuring that each CobaltStrike Client has the latest, accurate data concerning MemFiles status within Beacons and configuration:

New Clients connecting to the TS and needing the current memtable  
Instances where only a single Client is connected to the TS and restarts CobaltStrike (thus losing the memtable stored in the Client memory)  
Client A making a change to MemFiles data which must be communicated to Client B  

A multi-pronged approach was taken to address these scenarios. To handle the case where only a single CobaltStrike Client is connected to the TS (and thus is the only entity that has the memtable data), each time the Client alters the memtable (meminit, memclean) it also writes the contents of it's memtable out to a local text file located in the CobaltStrike directory. Should the Client exit/restart, or when MemFiles.cna is reloaded, it will first attempt to read from the local memtable.txt file in order to populate it's in-memory memtable.

When multiple Clients are connected to a TS and a new Client joins (as per the Event Log), each Client fetches a list of all users connected to the TS and sorts it alphabetically. The Client that is first on that list is selected as the "Broadcast" Client, and after waiting 5 seconds (to allow the new Client to initialize and read it's local memtable.txt) will send messages (Actions) in the Event Log for each entry in it's memtable. All Clients (aside from the Broadcasting one) will read these messages and update their memtable with the broadcast information; this includes updating existing entries as well as adding any additional ones that their respective memtable does not contain.

Normal operations involving MemFiles also rely on sending messages in the Event Log. When Client A runs meminit, a message is broadcast containing all of the pertinent memtable information; ALL Clients update their respective memtable by parsing these broadcasted Event Log messages using the "on Event_Action" hook. Changes are also made to MemFiles data when meminit finishes executing it's BOF; these changes are communicated back by Beacon (e.g. after running meminit, Beacon calls back with the memory location of the pMemAddrs struct) and as such are visible to all connected Clients, which update their respective memtable using the "on Beacon_Output" hook.

These separate efforts combined result in MemFiles being able to efficiently and reliably synchronize critical data between multiple Clients.

## Credits and Acknowledgements 
This project would not be possible without the contributions of the following individuals and projects:

1. [x64-NTAPI-inline-hook](https://github.com/globalpolicy/x64-NTAPI-inline-hook/blob/master/x64_inline_NTAPI_hooking.c) by globalpolicy  
2. [x64 Function Hooking by Example](http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html) by Kyle Halladay
3. [ShellcodeTemplate](https://github.com/Cracked5pider/ShellcodeTemplate) by Cracked5pider AKA @C5pider
4. @ilove2pwn_, by proxy of Cracked5pider  
5. [DLL-Exports-Extraction-BOF](https://github.com/EspressoCake/DLL-Exports-Extraction-BOF/blob/main/src/main.c) by EspressoCake AKA @the_bit_diddler
6. @anthemtotheego, by proxy of EspressoCake 
7. @Cr0Eax, by proxy of @anthemtotheego
8. @EthicalChaos, by proxy of @anthemtotheego  
9. [SysWhispers is dead, long live SysWhispers!](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/) by KlezVirus  
10. @yarden_shafir  
11. @DexterGerig  
