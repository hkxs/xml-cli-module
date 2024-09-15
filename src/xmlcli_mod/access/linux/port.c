#include<sys/io.h>
#include<unistd.h>
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>

uint8_t *read_port(uint16_t port, uint8_t size)
{
  // Get access to all ports on the system
  iopl(3);

  // Allocate our array to hold port reads
  uint8_t *val = malloc(sizeof(uint8_t) * size);

  if (!val) {  // handle condition if malloc referenced to null pointer reference
    free(val);
    return 0;
  } else {
    // Read one byte from each port up to the size we want
    int r;
    for(r = 0; r < size; r++)
    {
      uint8_t byte = inb(port + r);
      val[r] = byte;
    }

    return val;
  }
}

void write_port(uint16_t port, uint8_t size, uint32_t val)
{
  // Get access to all ports on the system
  iopl(3);

  int r;
  for(r = 0; r < size; r++)
  {
    uint8_t byteToWrite = ((val >> (8 * r)) & 0xFF);
    outb(byteToWrite, port + r);
  }
}
