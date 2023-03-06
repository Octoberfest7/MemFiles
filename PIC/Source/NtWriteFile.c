#include <Core.h>
#include <Win32.h>

SEC( text, B ) NTSTATUS Entry( HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key ) 
{
    INSTANCE Instance = { };

    Instance.Modules.Kernel32   = LdrModulePeb( HASH_KERNEL32 ); 
    Instance.Modules.Ntdll      = LdrModulePeb( HASH_NTDLL ); 
    
    if ( Instance.Modules.Kernel32 != NULL )
    {
        // Load needed functions
        Instance.Win32.LoadLibraryA = LdrFunction( Instance.Modules.Kernel32, 0xb7072fdb );
        
        // Load needed Libraries
        Instance.Modules.MSVCRT     = Instance.Win32.LoadLibraryA( GET_SYMBOL( "msvcrt" ) );
        
        //Populate MSVCRT functions
        if ( Instance.Modules.MSVCRT != NULL ) 
        {
            Instance.Win32.wcsstr = LdrFunction( Instance.Modules.MSVCRT, 0xd7bb2ceb );
            Instance.Win32.wcslen = LdrFunction( Instance.Modules.MSVCRT, 0xd7bb0d31 );
            Instance.Win32.wcscmp = LdrFunction( Instance.Modules.MSVCRT, 0xd7bae7f2 );
            Instance.Win32.malloc = LdrFunction( Instance.Modules.MSVCRT, 0xc03f707d );
            Instance.Win32.memset = LdrFunction( Instance.Modules.MSVCRT, 0xc0887b70 );
            Instance.Win32.memcpy = LdrFunction( Instance.Modules.MSVCRT, 0xc08838d0 );
            Instance.Win32.free = LdrFunction( Instance.Modules.MSVCRT, 0x7c84d807 );
            Instance.Win32.sprintf_s = LdrFunction( Instance.Modules.MSVCRT, 0xe32a7d7d );
        } 
    }

	//Placeholder string gets patched in with address of pFileInfo struct before it is injected
	char* pFileInfoStr = GET_SYMBOL( "AAAAAAAAAAAAAAAA" );

	//This routine to transform pFileInfoStr to a ull so we can create our struct: https://stackoverflow.com/a/39052987/18776214
	//Using things like stoull or strtoi64 altered the PIC EXE, forcing the trampoline function call at the end to use a CALL instruction rather than a JMP. 
	//This messed all kinds of things up, so using this snippet to achieve the same result without an API.
	unsigned long long val = 0;
	while (*pFileInfoStr) {
		// get current character then increment
		uint8_t byte = *pFileInfoStr++;
		// transform hex character to the 4bit equivalent number, using the ascii table indexes
		if (byte >= '0' && byte <= '9') byte = byte - '0';
		else if (byte >= 'a' && byte <= 'f') byte = byte - 'a' + 10;
		else if (byte >= 'A' && byte <= 'F') byte = byte - 'A' + 10;
		// shift 4 to make space for new digit, and add the 4 bits of the new digit 
		val = (val << 4) | (byte & 0xF);
	}

	//Create struct
	struct FileInfo* pFileInfo = (struct FileInfo*)val;

	//First things first, we need to see if the FileHandle value is in our FileInfo struct in order to determine if this call to NtWriteFile concerns one of our in-memory files
	BOOL matchfound = FALSE;
	int i;
	for (i = 0; i < pFileInfo->numFiles; i++)
	{
		//If we find a match
		if (pFileInfo->filehandle[i] == FileHandle)
		{
			//Set FileHandle == the corresponding handle in FileInfo
			//printf("We found a handle match in NtWriteFile!\n");

			matchfound = TRUE;
			break;
		}
	}

	//If we found a match, we are going to be writing the buffer to memory instead of to file
	if (matchfound)
	{		
		//If we don't have enough memory left in our buffer we need to double it until we do
		//This condition can be reached one of two ways dependent on whether the writing program manipulates the file pointer or not
		//1. buffer allocated - length of data written is less than the Length of data we have to write -> we need to increase the buffer size
		//2. filepointer + length offset is greater than the end position of the buffer allocated -> we need to increase the buffer size
		if ((ULONG)(pFileInfo->fileallocationlen[i] - pFileInfo->filedatalen[i]) < Length || (ULONG)pFileInfo->filedata[i] + (ULONG)pFileInfo->filepointer[i] + Length > (ULONG)pFileInfo->filedata[i] + (ULONG)pFileInfo->fileallocationlen[i])
		{
			while (TRUE)
			{
				//Double our allocation length
				pFileInfo->fileallocationlen[i] = pFileInfo->fileallocationlen[i] * 2;

				//Determine how much empty space is left in our buffer.
				ULONG freemem = (ULONG)(pFileInfo->fileallocationlen[i] - pFileInfo->filedatalen[i]);

				//Once we have enough freemem, break
				//Note we are going to increase buffer size until we are good for either conditions specified above
				if(freemem > Length && (ULONG)pFileInfo->filedata[i] + (ULONG)pFileInfo->filepointer[i] + Length < (ULONG)pFileInfo->filedata[i] + (ULONG)pFileInfo->fileallocationlen[i])
					break;
			}
			//Now allocate a new buffer + copy our existing data into it
			char* newbuf = Instance.Win32.malloc(pFileInfo->fileallocationlen[i] * sizeof(char));
            Instance.Win32.memset(newbuf, 0, pFileInfo->fileallocationlen[i] * sizeof(char));
			Instance.Win32.memcpy(newbuf, pFileInfo->filedata[i], pFileInfo->filedatalen[i]);

			//Free old buf
			Instance.Win32.free(pFileInfo->filedata[i]);

			//Set the FileInfo data pointer to our newly allocated buffer
			pFileInfo->filedata[i] = newbuf;
		}

		//Copy new data into buffer at the offset indicated by the filepointer
		Instance.Win32.memcpy(pFileInfo->filedata[i] + pFileInfo->filepointer[i], Buffer, Length);

		//Update FileData data length with written bytes
		pFileInfo->filedatalen[i] = pFileInfo->filedatalen[i] + Length;

		//Set IOStatusBlock member with length of data written
		IoStatusBlock->Information = Length;
		IoStatusBlock->Status = STATUS_SUCCESS;

		//Update filepointer location to the end of the data we wrote
		pFileInfo->filepointer[i] = pFileInfo->filepointer[i] + Length;

		//Return NTSTATUS
		return STATUS_SUCCESS;
	}

	//Otherwise we are going to patch back to the original NtWriteFile with the trampoline
	else
	{
		_NtWriteFile f = (_NtWriteFile)pFileInfo->NtWriteFiletrampoline;
		return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	}
}