#include <Core.h>
#include <Win32.h>

SEC( text, B ) NTSTATUS Entry( HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass ) 
{
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

	//First things first, we need to see if the Handle value is in our FileInfo struct in order to determine if this call to NtQueryInformationFile concerns one of our in-memory files
	BOOL matchfound = FALSE;
	int i;
	for (i = 0; i < pFileInfo->numFiles; i++)
	{
		//If we find a match
		if (pFileInfo->filehandle[i] == FileHandle)
		{
			matchfound = TRUE;
			break;
		}
	}

	//If we found a match, we are simply going to return STATUS_SUCCESS to avoid any 'invalid handle' errors
	if (matchfound)
	{
		return STATUS_SUCCESS;
	}

	//Otherwise we are going to patch calls back to the original NtQueryInformationFile with the trampoline
	else
	{
		_NtQueryInformationFile f = (_NtQueryInformationFile)pFileInfo->NtQueryInformationFiletrampoline;
		return f(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	}
} 