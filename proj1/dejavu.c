#include <stdio.h>

void deja_vu()
{
  /* Hopefully we won't see two black cats running through... */
  char door[8];
  gets(door);
}

int main()
{
  deja_vu();
  return 0;
}

// buffer - 8 bytes
// stack frame pointer - 4 bytes
// return address - 4 bytes 