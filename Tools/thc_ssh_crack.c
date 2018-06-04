/*
 * THC/2003
 *
 * Simple ssh-private key cracker. Tries to brute force (dictionary
 * attack) almost any ssh private key file format.
 *
 * This is just a quick tool from THC. Using OpenSSL is not really
 * fast...
 *
 * COMPILE:
 *     gcc -Wall -O2 -o thc-ssh-crack thc-ssh-crack.c -lssl
 *
 * RUN:
 * John is a good password generator. We use it for thc-ssh-crack:
 * 
 * $ john -stdout -incremental | nice -19 thc-ssh-crack id_dsa
 *
 * Normal dictionary (without john's permutation engine):
 *
 * $ nice -19 thc-ssh-crack id_dsa <dictionary.txt
 *
 * Enjoy,
 *
 * http://www.thc.org
 */
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>

int
main(int argc, char *argv[])
{
	FILE *fp = fopen(argv[1], "r");
	EVP_PKEY *pk;
	char *ptr;
	char pwd[1024];

	SSL_library_init();
	pwd[0] = '\0';
	while (1)
	{
		if (!fgets(pwd, sizeof pwd, stdin))
		{
			printf("Password not found.\n");
			exit(0);
		}
		ptr = strchr(pwd, '\n');
		if (ptr)
			*ptr = '\0';
		pk = PEM_read_PrivateKey(fp, NULL, NULL, (char *)pwd);
		if (pk)
		{
			printf("THC THC THC THC THC THC THC THC THC\n");
			printf("----> pwd is '%s' <-----\n", pwd);
			printf("THC THC THC THC THC THC THC THC THC\n");
			exit(0);
		}
	}

	return 0;
}


