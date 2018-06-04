/*
* This is a little smb OS-detection tool which gets workgroup, smbserver and OS
* works for all tested samba versions on different platforms 
* like: macosx,aix,solaris,linux,bsd and all Windows platforms !
* below you can see some sample outputs:
* 
* Windows 2003 gives me:
* Remote OS:
* ----------
* WINDOMAIN1
* Windows Server 2003 5.2
* Windows Server 2003 3790
* 
* Windows NT gives me:
* Remote OS:
* ----------
* WINDOMAIN2
* NT LAN Manager 4.0
* Windows NT 4.0
* 
* Windows 2k gives me:
* Remote OS:
* ----------
* WINDOMAIN3
* Windows 2000 LAN Manager
* Windows 5.0
* 
* Windows XP gives me:
* Remote OS:
* ----------
* WINDOMAIN4
* Windows 2000 LAN Manager
* Windows 5.1
* 
* Samba gives me:
* Remote OS:
* ----------
* SAMBADOMAIN1
* Samba 2.0.7
* Unix
*
* COMPILE:
*	cl THCsmbgetOS.c
*
* RUN:
* 	C:\ccode\THCsmbgetOS>THCsmbgetOS.exe gnpctx01
*
* -------------------------------------------------------
*  THCsmbgetOS v0.1 - gets group, server and os via SMB
*      by Johnny Cyberpunk (jcyberpunk@thc.org)
* -------------------------------------------------------
*
* [*] Connecting Port 139....
* [*] Sending session request....
* [*] Sending negotiation request....
* [*] Sending setup account request....
* [*] Successful....
*
* Remote OS:
* ----------
* MYNTDOMAIN
* Windows Server 2003 5.2
* Windows Server 2003 3790
*
* Enjoy,
*
* http://www.thc.org
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

char sessionrequest[] =
"\x81\x00\x00\x44\x20\x43\x4b\x46\x44\x45\x4e\x45\x43\x46\x44\x45"
"\x46\x46\x43\x46\x47\x45\x46\x46\x43\x43\x41\x43\x41\x43\x41\x43"
"\x41\x43\x41\x43\x41\x00\x20\x45\x4b\x45\x44\x46\x45\x45\x49\x45"
"\x44\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43"
"\x41\x43\x41\x43\x41\x41\x41\x00";

char negotiate[] =
"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x02"
"\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e"
"\x31\x32\x00";

char setupaccount[] =
"\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5c\x02"
"\x00\x00\x00\x00\x0d\xff\x00\x00\x00\xff\xff\x02\x00\x5c\x02\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0b"
"\x00\x00\x00\x4a\x43\00\x41\x54\x54\x48\x43\x00";

int main(int argc, char *argv[])
{  
  unsigned short smbport=139;
  unsigned char *infobuf;
  unsigned int sock,addr,i;
  int rc;
  struct sockaddr_in smbtcp;
  struct hostent * hp;
  WSADATA wsaData;
  unsigned int zeroc=0;

  printf("\n-------------------------------------------------------\n");
  printf(" THCsmbgetOS v0.1 - gets group, server and os via SMB\n");
  printf("       by Johnny Cyberpunk (jcyberpunk@thc.org)\n");
  printf("-------------------------------------------------------\n");
  
  if(argc<2)
  {
   printf("gimme host or ip\n");
   exit(-1);
  }
 
  if (WSAStartup(MAKEWORD(2,1),&wsaData) != 0)
  {
   printf("WSAStartup failed !\n");
   exit(-1);
  }
  
  hp = gethostbyname(argv[1]);

  if (!hp){
   addr = inet_addr(argv[1]);
  }
  if ((!hp)  && (addr == INADDR_NONE) )
  {
   printf("Unable to resolve %s\n",argv[1]);
   exit(-1);
  }

  sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (!sock)
  { 
   printf("socket() error...\n");
   exit(-1);
  }
  
  if (hp != NULL)
   memcpy(&(smbtcp.sin_addr),hp->h_addr,hp->h_length);
  else
   smbtcp.sin_addr.s_addr = addr;

  if (hp)
   smbtcp.sin_family = hp->h_addrtype;
  else
   smbtcp.sin_family = AF_INET;

  smbtcp.sin_port=htons(smbport);
 
  infobuf=malloc(256);
  memset(infobuf,0,256);

  printf("\n[*] Connecting Port 139....\n");
 
  rc=connect(sock, (struct sockaddr *) &smbtcp, sizeof (struct sockaddr_in));
  if(rc==0)
  {
    printf("[*] Sending session request....\n");
    send(sock,sessionrequest,sizeof(sessionrequest)-1,0);
    Sleep(500);
    rc=recv(sock,infobuf,256,0);
    if(rc<0)
    {
    	printf("error = %d (rc=%u)\n\n",WSAGetLastError(),rc);
    	return (-1);
    }
    memset(infobuf,0,256);
    printf("[*] Sending negotiation request....\n");
    send(sock,negotiate,sizeof(negotiate)-1,0);
    Sleep(500);
    rc=recv(sock,infobuf,256,0);
    if(rc<0)
    {
     printf("error = %d (rc=%u)\n\n",WSAGetLastError(),rc);
     return (-2);
    }
    memset(infobuf,0,256);
    printf("[*] Sending setup account request....\n");
    send(sock,setupaccount,sizeof(setupaccount)-1,0);
    Sleep(500);
    rc=recv(sock,infobuf,256,0);
    if(rc<0)
    {
     printf("error = %d (rc=%u)\n\n",WSAGetLastError(),rc);
     return (-3);
    }
    else if (rc==0)
    {
     printf("[*] Successful....\n");   	
     printf("\nRemote OS:\n");
     printf("----------");
     printf("\nI got back a null buffer ! WINXP sometimes does it\n");
    } 
    else
    {
     printf("[*] Successful....\n");   	
     printf("\nRemote OS:\n");
     printf("----------");
     i=rc;
     while ((--i>0)&&(zeroc<4)) 
     {
      if (infobuf[i]==0x00)
      {
       printf("%s\n",(char *)&(infobuf[i+1]));
       zeroc++;
      }
     }
    }
    
    printf("\n\n");
  }
  else
   printf("can't connect to smb port 139!\n");
  
  shutdown(sock,1);
  closesocket(sock);
  free(infobuf);
  exit(0);
}
