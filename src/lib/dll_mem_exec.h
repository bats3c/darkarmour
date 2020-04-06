typedef struct {
  int   size;
  char  *vubuffer;
  unsigned char *bytes;
} exploit_info;

typedef struct {
  int   fd;
  int   file_size;
  DWORD pid;
} pe;
