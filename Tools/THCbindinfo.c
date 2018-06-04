/*
 * THC/2004
 * 
 * This is just a quick and dirty hack to grab the Version of ISC bind 8+9
 * nameservers. It detects the difference between bind 8+9 even if the version
 * has been disguised.
 * The code is 2 years old and i never shared it before, but as we
 * opened a tool section now, i think it's worth to share it to the public.
 *
 * COMPILE (with Microsoft C++): 
 * 	cl THCbindinfo.c
 *
 * RUN:
 * 	C:\ccode\THCbindinfo>THCbindinfo.exe 10.65.57.153
 * 
 * ----------------------------------------
 * DNS Version Query for BIND 8+9 Servers
 *       coding jcyberpunk@thc.org
 * ----------------------------------------
 *
 * Query for : 10.65.57.153 in progress...pleaze wait!
 * 
 * ahh...that must be a bind 8...trying to get more details...
 * 
 * DNS Version : BIND 8.3.4
 * 
 * Enjoy,
 * 
 * http://www.thc.org
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>

#define TIMEOUT 5 
#define errno WSAGetLastError()

#define STATUS_FAILED 0xFFFF

#pragma comment(lib, "ws2_32.lib")

void usage();

main(int argc,char **argv)
{
  struct sockaddr_in myudp;
  struct hostent * hp;
  SOCKET udpsock;
  unsigned short port=53;
  unsigned int addr=0;
  fd_set r;
  struct timeval mytimeout;

  char data[30]= {0x00,0x06,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x76,0x65,0x72,0x73,0x69,0x6f,0x6e,0x04,0x62,0x69,0x6e,0x64,0x00,0x00,0x10,0x00,0x03};
  unsigned char *dataout;
  unsigned int error, open;

  WSADATA wsaData;

  printf("\n----------------------------------------\n");
  printf("DNS Version Query for BIND 8+9 Servers\n");
  printf("      coding jcyberpunk@thc.org\n");
  printf("----------------------------------------\n\n");

  if(argc != 2)
  {
   usage();
   exit(-1);
  }

  if (WSAStartup(MAKEWORD(2,1),&wsaData) != 0)
  {
   fprintf(stderr,"WSAStartup failed: %d\n",GetLastError());
   ExitProcess(STATUS_FAILED);
  }

  memset(&myudp,0,sizeof(myudp));

  hp = gethostbyname(argv[1]);

  if (!hp){
   addr = inet_addr(argv[1]);
  }
  if ((!hp)  && (addr == INADDR_NONE) )
  {
   fprintf(stderr,"Unable to resolve %s\n",argv[1]);
   ExitProcess(STATUS_FAILED);
  }

  if (hp != NULL)
   memcpy(&(myudp.sin_addr),hp->h_addr,hp->h_length);
  else
   myudp.sin_addr.s_addr = addr;

  if (hp)
   myudp.sin_family = hp->h_addrtype;
  else
   myudp.sin_family = AF_INET;

  printf("Query for : %s in progress...pleaze wait!\n\n",inet_ntoa(myudp.sin_addr));
 
  dataout=(char*)malloc(100);
  memset(dataout,0,sizeof(*dataout));       


  mytimeout.tv_sec = TIMEOUT;
  mytimeout.tv_usec = 0;

   myudp.sin_port = htons(port);

   if ((udpsock = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
   {
     printf("error binding socket!\n");
	 exit(0);
   }

   if (connect (udpsock, (struct sockaddr *) &myudp, sizeof (
 	       struct sockaddr_in)) == 0)
   {

      FD_ZERO (&r);
      FD_SET (udpsock, &r);
	  mytimeout.tv_sec = TIMEOUT;
	  mytimeout.tv_usec = 0;

      send (udpsock, data, sizeof data, 0);
	  error = select ((udpsock + 1), &r, NULL, NULL, &mytimeout);

     if (error==0)
     {
      printf("Port 53 udp is up, but i haven't received data within 5 seconds.\n");
      printf("it seems that this is not a bind 8 or 9 ! :(\n");
      exit(-1);
     }
     if (error==-1)
     {
        printf("select error : %d\n",errno);
        exit(-1);
     }
      open = recv(udpsock, dataout, 100, 0);
      if (open==-1)
	  {
	    printf("sorry, no nameserver running :(\n");
		exit(-1);
	  }

	  dataout[open]=0;
      if ((dataout[3]&127)==0)
	  {
		 if(dataout[30]==192)
		 {
		  printf ("ahh...that must be a bind 9...trying to get more details...\n\n");
		  printf ("DNS Version : %s\n",dataout+43);
		 }
		 else
		 {
		  printf ("ahh...that must be a bind 8...trying to get more details...\n\n");
          printf("DNS Version : %s\n",dataout+55);
		 }
	  }
      else
         printf("DNS Version : unknown\n");

    shutdown(udpsock,1);
    closesocket(udpsock);
   }
   
   else
    printf("connect () error : %d\n",errno);

   free(dataout);

  exit(0);
}

void usage()
{
 printf("Gimme <Hostname|IP-Address>\n");
 exit(-1);
}
