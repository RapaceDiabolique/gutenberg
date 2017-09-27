#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

int
main(void)
{
  char * line = NULL;
  size_t len = 0;
  ssize_t read;

  read = getline(&line, &len, stdin);
  if (read != -1)
    printf(line);
  return 0;
}
