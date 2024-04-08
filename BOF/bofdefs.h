#pragma once
#include <windows.h>
#include <stdio.h>
#include <corecrt.h>
#include <winternl.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <inttypes.h>
#include <tlhelp32.h>

#define MF_FILE_INFO_KEY "MemFilesKey"

//MSVCRT
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void *__cdecl MSVCRT$malloc(size_t size);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char*);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void*, void*, size_t);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI int __cdecl MSVCRT$sprintf_s(char* buffer, size_t sizeOfBuffer, const char* format, ...);
WINBASEAPI __int64 __cdecl MSVCRT$_strtoi64(const char* strSource, char** endptr, int base);
WINBASEAPI int __cdecl MSVCRT$rand();
WINBASEAPI void __cdecl MSVCRT$srand(int initial);
WINBASEAPI time_t __cdecl MSVCRT$time(time_t *time);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void* buffer1, const void* buffer2, size_t count);

//K32
WINBASEAPI BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte (UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR lpModuleName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpfOldProtect);
WINBASEAPI int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess();

//MSVCRT
#define free                        MSVCRT$free
#define malloc                      MSVCRT$malloc
#define strlen                      MSVCRT$strlen
#define memcpy                      MSVCRT$memcpy
#define calloc                      MSVCRT$calloc
#define memset                      MSVCRT$memset
#define wcslen                      MSVCRT$wcslen
#define sprintf_s                   MSVCRT$sprintf_s
#define _strtoi64                   MSVCRT$_strtoi64
#define rand                        MSVCRT$rand
#define srand                       MSVCRT$srand
#define time                        MSVCRT$time
#define memcmp                      MSVCRT$memcmp

//K32
#define ReadProcessMemory           KERNEL32$ReadProcessMemory
#define WriteProcessMemory          KERNEL32$WriteProcessMemory
#define GetCurrentProcess           KERNEL32$GetCurrentProcess 
#define WideCharToMultiByte         KERNEL32$WideCharToMultiByte
#define GetProcAddress              KERNEL32$GetProcAddress
#define VirtualAlloc                KERNEL32$VirtualAlloc
#define VirtualFree                 KERNEL32$VirtualFree
#define VirtualProtect 				KERNEL32$VirtualProtect
#define GetModuleHandleW            KERNEL32$GetModuleHandleW

struct FileInfo {
    HANDLE filehandle[100];                         // A fake, unique handle used to associate the NtCreateFile call with later calls to NtWriteFile and NtClose
    wchar_t* filename[100];                         // The name of the file as passed in the first NtCreateFile call
    char* filedata[100];                            // The actual data that is written to memory by NtWriteFile
    int filedatalen[100];                           // The length of the data that has been written to memory by NtWriteFile
    int filepointer[100];                           // The location of the file pointer as manipulated by NtSetInformationFile
    int fileallocationlen[100];                     // The size of the memory allocation for the file where the data is stored
    BOOL fileclosed[100];                           // Boolen representing whether the "handle" has been closed, indicating no further calls to NtWriteFile are expected
    int numFiles;                                   // The number of files/entries currently present in the FileInfo array (where each index == a file).  Increments and Decrements during lifetime of program
    int totalFiles;                                 // The total number of files written into FileInfo. Only increments. Used to assign the "handle" for each entry in FileInfo
    void** PICNtCreateFile;                         // Memory address of injected NtCreateFile PIC code
    void** PICNtWriteFile;                          // Memory address of injected NtWriteFile PIC code
    void** PICNtClose;                              // Memory address of injected NtClose PIC code
    void** PICNtQueryVolumeInformationFile;         // Memory address of injected NtQueryVolumeInformationFile PIC code
    void** PICNtQueryInformationFile;               // Memory address of injected NtQueryInformationFile PIC code
    void** PICNtSetInformationFile;                 // Memory address of injected NtSetInformationFile PIC code
    void** PICNtReadFile;                           // Memory address of injected NtReadFile PIC code
    void** PICNtOpenFile;                           // Memory address of injected NtOpenFile PIC code
    void** PICNtFlushBuffersFile;                   // Memory address of injected NtFlushBuffersFile PIC code
    int PICNtCreateFileLen;                         // length of injected NtCreateFile PIC code
    int PICNtWriteFileLen;                          // length of injected NtWriteFile PIC code
    int PICNtCloseLen;                              // length of injected NtClose PIC code
    int PICNtQueryVolumeInformationFileLen;         // length of injected NtQueryVolumeInformationFile PIC code
    int PICNtQueryInformationFileLen;               // length of injected NtQueryInformationFile PIC code
    int PICNtSetInformationFileLen;                 // length of injected NtSetInformationFile PIC code
    int PICNtReadFileLen;                           // length of injected NtReadFile PIC code
    int PICNtOpenFileLen;                           // length of injected NtOpenFile PIC code
    int PICNtFlushBuffersFileLen;                   // length of injected NtFlushBuffersFile PIC code
    LPVOID NtCreateFiletrampoline;                  // Trampoline for normal NtCreateFile calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtWriteFiletrampoline;                   // Trampoline for normal NtWriteFile calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtClosetrampoline;                       // Trampoline for normal NtClose calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtQueryVolumeInformationFiletrampoline;  // Trampoline for normal NtQueryVolumeInformationFile calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtQueryInformationFiletrampoline;        // Trampoline for normal NtQueryInformationFile calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtSetInformationFiletrampoline;          // Trampoline for normal NtSetInformationFile calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtReadFiletrampoline;                    // Trampoline for normal NtReadFile calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtOpenFiletrampoline;                    // Trampoline for normal NtOpenFile calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtFlushBuffersFiletrampoline;            // Trampoline for normal NtFlushBuffersFile calls to redirect execution back to original function/maintain normal functionality
    LPVOID NtCreateFileorigbytes;                   // origbytes for normal NtCreateFile for restoring later
    LPVOID NtWriteFileorigbytes;                    // origbytes for NtWriteFile for restoring later
    LPVOID NtCloseorigbytes;                        // origbytes for NtClose for restoring later
    LPVOID NtQueryVolumeInformationFileorigbytes;   // origbytes for NtQueryVolumeInformationFile for restoring later
    LPVOID NtQueryInformationFileorigbytes;         // origbytes for NtQueryInformationFile for restoring later
    LPVOID NtSetInformationFileorigbytes;           // origbytes for NtSetInformationFile for restoring later
    LPVOID NtReadFileorigbytes;                     // origbytes for NtReadFile for restoring later
    LPVOID NtOpenFileorigbytes;                     // origbytes for NtOpenFile for restoring later
    LPVOID NtFlushBuffersFileorigbytes;             // origbytes for NtFlushBuffersFile for restoring later
};