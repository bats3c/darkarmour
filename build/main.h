#define key0 0x4f
#define key1 0x58
#define key2 0x31
#define key3 0x1e
#define key4 0x4e

VOID FixImageIAT(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header);
LPVOID MapImageToMemory(LPVOID base_addr);
