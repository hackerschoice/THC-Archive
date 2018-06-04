/*
 * descambles cisco IOS type-7 passwords
 * found somewhere on the internet, slightly modified, anonymous@segfault.net
 *
 * gcc -Wall -o ciscocrack ciscocrack.c
 * ./ciscocrack 01178E05590909022A
 *
 */

#include <stdio.h>
#include <ctype.h>

char xlat[] = {
        0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
        0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
        0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 
        0x55, 0x42 
};


int
cdecrypt(char *enc_pw, char *dec_pw)
{
        unsigned int seed, i, val = 0;

        if(strlen(enc_pw) & 1)
                return(-1);

        seed = (enc_pw[0] - '0') * 10 + enc_pw[1] - '0';

        if (seed > 15 || !isdigit(enc_pw[0]) || !isdigit(enc_pw[1]))
                return(-1);

        for (i = 2 ; i <= strlen(enc_pw); i++) {
                if(i !=2 && !(i & 1)) {
                        dec_pw[i / 2 - 2] = val ^ xlat[seed++];
                        val = 0;
                }

                val *= 16;

                if(isdigit(enc_pw[i] = toupper(enc_pw[i]))) {
                        val += enc_pw[i] - '0';
                        continue;
                }

                if(enc_pw[i] >= 'A' && enc_pw[i] <= 'F') {
                        val += enc_pw[i] - 'A' + 10;
                        continue;
                }

                if(strlen(enc_pw) != i)
                        return(-1);
        }

        dec_pw[++i / 2] = 0;

        return(0);
}

void
usage()
{
        fprintf(stdout, "Usage: ciscocrack <encrypted password>\n");
}

int
main(int argc, char *argv[])
{
    char passwd[65];

    memset(passwd, 0, sizeof(passwd));

    if(argc != 2)
    {
          usage();
          exit(1);
    }

    if(cdecrypt(argv[1], passwd)) {
          fprintf(stderr, "Error.\n");
          exit(1);
    }
    printf("Passwd: %s\n", passwd);

    return 0;
}
