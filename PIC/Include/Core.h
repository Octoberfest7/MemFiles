
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <conio.h>
#include <Macros.h>
#include <inttypes.h>

UINT_PTR GetRIP( VOID );

typedef struct {

    struct {
        WIN32_FUNC( LoadLibraryA );
        WIN32_FUNC( wcsstr );
        WIN32_FUNC( wcslen );
        WIN32_FUNC( wcscmp );
        WIN32_FUNC( malloc );
        WIN32_FUNC( memset );
        WIN32_FUNC( memcpy );
        WIN32_FUNC( free );
        WIN32_FUNC( sprintf_s );
    } Win32; 

    struct {
        // Basics
        HMODULE     Kernel32;
        HMODULE     Ntdll;
        HMODULE     MSVCRT
    } Modules;

} INSTANCE, *PINSTANCE;

typedef long NTSTATUS;

typedef NTSTATUS(__stdcall* _NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

typedef NTSTATUS(__stdcall* _NtWriteFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

typedef NTSTATUS(__stdcall* _NtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

typedef NTSTATUS(__stdcall* _NtClose)(
    HANDLE Handle
    );

typedef NTSTATUS(__stdcall* _NtQueryVolumeInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FS_INFORMATION_CLASS FsInformationClass
    );

typedef NTSTATUS(__stdcall* _NtQueryInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FsInformationClass
    );

typedef NTSTATUS(__stdcall* _NtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FsInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FsInformationClass
    );

typedef NTSTATUS(__stdcall* _NtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

typedef NTSTATUS(__stdcall* _NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG  ShareAccess,
    ULONG OpenOptions
    );

typedef NTSTATUS(__stdcall* _NtFlushBuffersFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock
    );

#define STATUS_SUCCESS 0x00000000;
#define FILE_DEVICE_DISK 0x00000007;

struct FileInfo {
    HANDLE filehandle[100];                         // A fake, unique handle used to associate the NtCreateFile call with later calls to NtWriteFile and NtClose
    wchar_t* filename[100];                         // The name of the file as passed in the first NtCreateFile call
    char* filedata[100];                            // The actual data that is written to memory by NtWriteFile
    int filedatalen[100];                           // The length of the data that has been written to memory by NtWriteFile
    int fileallocationlen[100];                     // The size of the memory allocation for the file where the data is stored
    BOOL fileclosed[100];                           // Boolen representing whether the "handle" has been closed, indicating no further calls to NtWriteFile are expected
    int numFiles;                                   // The number of files/entries currently present in the FileInfo array (where each index == a file).  Increments and Decrements during lifetime of program
    int totalFiles;                                 // The total number of files written into FileInfo. Only increments. Used to assign the "handle" for each entry in FileInfo
    void** PICNtCreateFile;                          // Memory address of injected NtCreateFile PIC code
    void** PICNtWriteFile;                           // Memory address of injected NtWriteFile PIC code
    void** PICNtClose;                               // Memory address of injected NtClose PIC code
    void** PICNtQueryVolumeInformationFile;          // Memory address of injected NtQueryVolumeInformationFile PIC code
    void** PICNtQueryInformationFile;                // Memory address of injected NtQueryInformationFile PIC code
    void** PICNtSetInformationFile;                  // Memory address of injected NtSetInformationFile PIC code
    void** PICNtReadFile;                            // Memory address of injected NtReadFile PIC code
    void** PICNtOpenFile;                            // Memory address of injected NtOpenFile PIC code
    void** PICNtFlushBuffersFile;                    // Memory address of injected NtFlushBuffersFile PIC code
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