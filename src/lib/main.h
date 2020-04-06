#define key_one 0x29
#define key_two 0x22
#define null_key 0x2f
VOID FixImageIAT(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header);LPVOID MapImageToMemory(LPVOID base_addr);