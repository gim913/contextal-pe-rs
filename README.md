# PE processor

WiP, run with RUST\_LOG=info to display parsing information


Sample:
```
: cargo run --release -- c:\Windows\System32\ntdll.dll
--- PE FILE HEADER ---
Machine: 0x8664 (x64)
NumberOfSections: 11
TimeDateStamp: 2092-10-25 07:22:34 UTC
PointerToSymbolTable: 0x0
NumberOfSymbols: 0
SizeOfOptionalHeader: 240
Characteristics: ["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE", "DLL"]
--- IMAGE OPTIONAL HEADER ---
Magic: 0x20b (PE32+)
Subsystem: Windows character subsystem
SizeOfHeaders: 0x1000
NumberOfRvaAndSizes: 16
--- SECTION 1 HEADER ---
Name: .text
VirtualSize: 0x12d5ee
VirtualAddress: 0x1000
SizeOfRawData: 1236992
PointerToRawData: 4096
Characteristics: ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
--- SECTION 2 HEADER ---
Name: PAGE
VirtualSize: 0x58a
VirtualAddress: 0x12f000
SizeOfRawData: 4096
PointerToRawData: 1241088
Characteristics: ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
--- SECTION 3 HEADER ---
Name: RT
VirtualSize: 0x1cf
VirtualAddress: 0x130000
SizeOfRawData: 4096
PointerToRawData: 1245184
Characteristics: ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
--- SECTION 4 HEADER ---
Name: fothk
VirtualSize: 0x1000
VirtualAddress: 0x131000
SizeOfRawData: 4096
PointerToRawData: 1249280
Characteristics: ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
--- SECTION 5 HEADER ---
Name: .rdata
VirtualSize: 0x4d2f2
VirtualAddress: 0x132000
SizeOfRawData: 319488
PointerToRawData: 1253376
Characteristics: ["CNT_INITIALIZED_DATA", "MEM_READ"]
--- SECTION 6 HEADER ---
Name: .data
VirtualSize: 0xb388
VirtualAddress: 0x180000
SizeOfRawData: 16384
PointerToRawData: 1572864
Characteristics: ["CNT_INITIALIZED_DATA", "MEM_READ", "MEM_WRITE"]
--- SECTION 7 HEADER ---
Name: .pdata
VirtualSize: 0xed30
VirtualAddress: 0x18c000
SizeOfRawData: 61440
PointerToRawData: 1589248
Characteristics: ["CNT_INITIALIZED_DATA", "MEM_READ"]
--- SECTION 8 HEADER ---
Name: .mrdata
VirtualSize: 0x3540
VirtualAddress: 0x19b000
SizeOfRawData: 16384
PointerToRawData: 1650688
Characteristics: ["CNT_INITIALIZED_DATA", "MEM_READ", "MEM_WRITE"]
--- SECTION 9 HEADER ---
Name: .00cfg
VirtualSize: 0x28
VirtualAddress: 0x19f000
SizeOfRawData: 4096
PointerToRawData: 1667072
Characteristics: ["CNT_INITIALIZED_DATA", "MEM_READ"]
--- SECTION 10 HEADER ---
Name: .rsrc
VirtualSize: 0x759a8
VirtualAddress: 0x1a0000
SizeOfRawData: 483328
PointerToRawData: 1671168
Characteristics: ["CNT_INITIALIZED_DATA", "MEM_READ"]
--- SECTION 11 HEADER ---
Name: .reloc
VirtualSize: 0x624
VirtualAddress: 0x216000
SizeOfRawData: 4096
PointerToRawData: 2154496
Characteristics: ["CNT_INITIALIZED_DATA", "MEM_DISCARDABLE", "MEM_READ"]
c:\Windows\System32\ntdll.dll: ISSUES: ["PH_FUTURE_TIMESTAMP"]
```

[Why are the module timestamps in Windows 10 so nonsensical?](https://devblogs.microsoft.com/oldnewthing/20180103-00/?p=97705)
