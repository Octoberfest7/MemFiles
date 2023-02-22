ncf 			= NtCreateFile
nwf 			= NtWriteFile
nc 				= NtClose
nqvif  			= NtQueryVolumeInformationFile
nqif 			= NtQueryInformationFile
nsif 			= NtSetInformationFile
nrf 			= NtReadFile
nof 			= NtOpenFile
nfbf 			= NtFlushBuffersFile

CCX64			= x86_64-w64-mingw32-gcc
CCX86			= i686-w64-mingw32-gcc

CFLAGS			=  -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS 			+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  		+= -s -ffunction-sections -falign-jumps=1 -w
CFLAGS			+= -falign-labels=1 -fPIC -Wl,-TPIC/Scripts/Linker.ld
CFLAGS			+= -Wl,-s,--no-seh,--enable-stdcall-fixup

EXECUTABLE_ncf_X64		= PIC/Bin/$(ncf).x64.exe
RAWBINARY_ncf_X64		= PIC/Bin/$(ncf).x64.bin

EXECUTABLE_nwf_X64		= PIC/Bin/$(nwf).x64.exe
RAWBINARY_nwf_X64		= PIC/Bin/$(nwf).x64.bin

EXECUTABLE_nc_X64		= PIC/Bin/$(nc).x64.exe
RAWBINARY_nc_X64		= PIC/Bin/$(nc).x64.bin

EXECUTABLE_nqvif_X64	= PIC/Bin/$(nqvif).x64.exe
RAWBINARY_nqvif_X64		= PIC/Bin/$(nqvif).x64.bin

EXECUTABLE_nqif_X64		= PIC/Bin/$(nqif).x64.exe
RAWBINARY_nqif_X64		= PIC/Bin/$(nqif).x64.bin

EXECUTABLE_nsif_X64		= PIC/Bin/$(nsif).x64.exe
RAWBINARY_nsif_X64		= PIC/Bin/$(nsif).x64.bin

EXECUTABLE_nrf_X64		= PIC/Bin/$(nrf).x64.exe
RAWBINARY_nrf_X64		= PIC/Bin/$(nrf).x64.bin

EXECUTABLE_nof_X64		= PIC/Bin/$(nof).x64.exe
RAWBINARY_nof_X64		= PIC/Bin/$(nof).x64.bin

EXECUTABLE_nfbf_X64		= PIC/Bin/$(nfbf).x64.exe
RAWBINARY_nfbf_X64		= PIC/Bin/$(nfbf).x64.bin

all: pic bof

pic: picclean
	@ echo "[*] Compile x64 executables..."
	
	@ nasm -f win64 PIC/Source/Asm/x64/asm.s -o PIC/Bin/asm.x64.o
	
	@ $(CCX64) PIC/Source/NtCreateFile.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_ncf_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_ncf_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_ncf_X64) -o $(RAWBINARY_ncf_X64)

	@ $(CCX64) PIC/Source/NtWriteFile.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_nwf_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_nwf_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_nwf_X64) -o $(RAWBINARY_nwf_X64)

	@ $(CCX64) PIC/Source/NtClose.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_nc_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_nc_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_nc_X64) -o $(RAWBINARY_nc_X64)

	@ $(CCX64) PIC/Source/NtQueryVolumeInformationFile.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_nqvif_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_nqvif_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_nqvif_X64) -o $(RAWBINARY_nqvif_X64)

	@ $(CCX64) PIC/Source/NtQueryInformationFile.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_nqif_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_nqif_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_nqif_X64) -o $(RAWBINARY_nqif_X64)

	@ $(CCX64) PIC/Source/NtSetInformationFile.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_nsif_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_nsif_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_nsif_X64) -o $(RAWBINARY_nsif_X64)

	@ $(CCX64) PIC/Source/NtReadFile.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_nrf_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_nrf_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_nrf_X64) -o $(RAWBINARY_nrf_X64)	

	@ $(CCX64) PIC/Source/NtOpenFile.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_nof_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_nof_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_nof_X64) -o $(RAWBINARY_nof_X64)	

	@ $(CCX64) PIC/Source/NtFlushBuffersFile.c PIC/Source/Utils.c PIC/Source/Win32.c PIC/Bin/asm.x64.o -o $(EXECUTABLE_nfbf_X64) $(CFLAGS) $(LFLAGS) -IPIC/Include -masm=intel
	@ echo "[*] Extract shellcode: $(RAWBINARY_nfbf_X64)"
	@ python3 PIC/Scripts/extract.py -f $(EXECUTABLE_nfbf_X64) -o $(RAWBINARY_nfbf_X64)	

	@ rm $(EXECUTABLE_ncf_X64)
	@ rm $(EXECUTABLE_nwf_X64)
	@ rm $(EXECUTABLE_nc_X64)
	@ rm $(EXECUTABLE_nqvif_X64)
	@ rm $(EXECUTABLE_nqif_X64)
	@ rm $(EXECUTABLE_nsif_X64)
	@ rm $(EXECUTABLE_nrf_X64)
	@ rm $(EXECUTABLE_nof_X64) 
	@ rm $(EXECUTABLE_nfbf_X64)

bof: bofclean
	@ echo "[*] Compile BOFs..."
	@ $(CCX64) -c BOF/InstallHooks.c -o BOF/InstallHooks.x64.o -DBOF -Os 
	@ $(CCX64) -c BOF/MemFiles.c -o BOF/MemFiles.x64.o -DBOF -Os 

picclean:
	@ rm -rf PIC/Bin/*.o
	@ rm -rf PIC/Bin/*.bin
	@ rm -rf PIC/Bin/*.exe

bofclean:
	@ rm -rf BOF/*.o