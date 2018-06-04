/*
 * Keyfinder - finds crypto keys, encrypted data and compressed data in files
 *             by analyzing the entropy of parts of the file.
 *
 * (c) 2005 by van Hauser / THC <vh@thc.org> www.thc.org
 * The GPL 2.0 applies to this code.
 *
 * Based on the paper "Playing hide and seek with stored keys" by Shamir and
 * van Someren. www.ncipher.com/products/files/papers/anguilla/keyhide2.pdf
 *
 * In my experiments I went however a different route to identify keys which
 * seems to be better when identifying keys.
 * The paper evaluates 60 byte chunks on their entropy, and depending on the
 * number of consecutive chunks with high entropies, this could be the key.
 * This tool evalutes the full key size for the entropy, increasing by an
 * approx 10% of the key size windows. Hence if the key is 1024 bit = 128 byte
 * long, the window size is 10, and the file size is 500 bytes, it looks at
 * the randomness from bytes 0-128, then 10-138, next 20-148 etc.
 * Additionally to measuring the entropy, I added checking for the
 * arithmetical mean, and detecting couting bytes up- and downwards in the
 * beginning, middle or end of the file.
 * By having three randomness checks and evaluating the full key size with a
 * sliding window, the best keyfinding measures are in place, and much better
 * than in the described paper.
 * 
 * However still beware: you will 1) receive some false positives, and 2)
 * Keyfinder can not find the exact start/end region of the key, it will 
 * usually be some bytes before or after the reported file area.
 *
 * For usage hints, type "keyfinder -h"
 *
 * To compile: gcc -o keyfinder keyfinder.c -lm
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#define MINIMUM_RANDOMNESS  85
#define KEY_SIZE           128
#define WINDOW_SIZE         10
#define DUMP_ROWS           16

int minimal_randomness = MINIMUM_RANDOMNESS;
char *prg;
int ext_entropy;
int ext_mean;
int debug = 0;

void help() {
  printf("Keyfinder v1.0 (c) 2005 by van Hauser / THC <vh@thc.org> www.thc.org\n");
  printf("\nSyntax: %s [-k KEY_SIZE] [-w WINDOW_SIZE] [-r MINIMUM_RANDOMNESS] FILE\n", prg);
  printf("\nOptions:\n");
  printf("    -k KEY_SIZE            Key size to look for (default: %d byte [%d bit])\n", KEY_SIZE, KEY_SIZE * 8);
  printf("    -w WINDOW_SIZE         Window size to check (default: %d byte)\n", WINDOW_SIZE);
  printf("    -r MINIMUM_RANDOMNESS  Minimum %% of randomness for keys (default: %d%%)\n", MINIMUM_RANDOMNESS);
  printf("    -d                     Print debug output\n");
  printf("\nFinds binary crypto keys, crypto data and compressed data in files.\n");
  printf("The result is an indicator where the key could be, not a byte exact match.\n");
  printf("The randomness is calculated by the entropy, the arithmetic mean value and a\n");
  printf("counting check. Read more information in the header of the keyfinder.c file.\n");
  printf("Note:  If -k is specified but not -w, -w will be 10%% of -k.\n");
  printf("Hints: (1) the smaller -k, the smaller should be -r\n");
  printf("       (2) the smaller -r the more false positives\n");
  printf("       (3) -w should be 1/8 to 1/20 of -k\n");
  printf("       (4) -k values are 128/256/512 byte for RSA/asymmetric keys\n");
  printf("       (5) -k 512 -> -r 95; -k 128 -> -r 85 \n");
  exit(-1);
}

/* Why is log2() in libm not working?? what a fucking #!+~$$!! */
#define log2of10 3.32192809488736234787
static double log2_(double x) {
 return (log2of10 * (log10(x)));
}

void calculate_randomness(unsigned char *buf, int buflen) {
  double ent = 0.0;
  double mean = 0.0;
  double datasum = 0.0;
  unsigned long ccount[256];
  double prob[256];
  int i, j = 0;

  for (i = 0; i < 256; i++)
    ccount[i] = 0;

  for (i = 0; i < buflen; i++)
    ccount[buf[i]]++;

  for (i = 0; i < 256; i++) {
    prob[i] = (double) ccount[i] / buflen;
    datasum += ((double) i) * ccount[i]; /**/
  }

  for (i = 0; i < 256; i++) {
    if (prob[i] > 0.0) {
      ent += prob[i] * log2_((1.0 / prob[i]));
//      printf("%f += %f * %f\n", ent, prob[i], log2_((1.0 / prob[i])));
    }
  }

  mean = datasum / buflen; /**/
  ext_mean = (mean - 127.5) / 1.275;
  if (ext_mean < 0)
    ext_mean = ext_mean * -1;
  ext_mean = 100 - ext_mean;
  
  ext_entropy = (ent * 100) / 8;

  if (debug) {
    printf("Entropy: %f bits (8 is totally random)\n", ent);
    printf("Mean: %1.4f (127.5 is totally random)\n", mean);
  }

  if (ext_entropy + ext_mean >= minimal_randomness) {  
  /* check for counting in the beginning */
    for (i = 0; i < 8 && j == 0; i++)
      if (buf[i] + 1 != buf[i + 1])
        j = 1;
    if (j == 0)
      j = 2;
    if (j == 1)
      j = 0;
    for (i = 0; i < 8 && j == 0; i++)
      if (buf[i] - 1 != buf[i++ + 1])
        j = 1;
    if (j == 0)
      j = 2;
    if (j == 1)
      j = 0;

    /* check for counting in the middle */
    for (i = 0; i < 8 && j == 0; i++)
      if (buf[((buflen/2) - i) - 4] != buf[((buflen/2) - i) - 3] + 1)
        j = 1;
    if (j == 0)
      j = 2;
    if (j == 1)
      j = 0;
    for (i = 0; i < 8 && j == 0; i++)
      if (buf[((buflen/2) - i) - 4] != buf[((buflen/2) - i) - 3] - 1)
        j = 1;
    if (j == 0)
      j = 2;
    if (j == 1)
      j = 0;

    /* check for counting in the end */
    for (i = 1; i <= 8 && j == 0; i++)
      if (buf[buflen - i] != buf[(buflen - i) - 1] + 1)
        j = 1;
    if (j == 0)
      j = 2;
    if (j == 1)
      j = 0;
    for (i = 1; i <= 8 && j == 0; i++)
      if (buf[buflen - i] != buf[(buflen - i) - 1] - 1)
        j = 1;
    if (j == 0)
      j = 2;
    if (j == 1)
      j = 0;

    if (j == 2) {
      if (debug)
        printf("Counting detected, false positive, ignoring...\n");
      ext_mean = 0;
      ext_entropy = 0;
    }
  }
}

void dump_asciihex(unsigned char *string, int length, unsigned int offset) {
    unsigned char *p = (unsigned char *) string;
    unsigned char lastrow_data[16];
    unsigned int rows = length / DUMP_ROWS;
    unsigned int lastrow = length % DUMP_ROWS;
    unsigned int i, j;

    for (i = 0; i < rows; i++) {
        printf("%08hx:  ", i * 16 + offset);
        for (j = 0; j < DUMP_ROWS; j++) {
            printf("%02x", p[(i * 16) + j]);
            if (j % 2 == 1)
                printf(" ");
        }
        printf("   [ ");
        for (j = 0; j < DUMP_ROWS; j++) {
            if (isprint(p[(i * 16) + j]))
                printf("%c", p[(i * 16) + j]);
            else
                printf(".");
        }
        printf(" ]\n");
    }
    if (lastrow > 0) {
        memset(lastrow_data, 0, sizeof(lastrow_data));
        memcpy(lastrow_data, p + length - lastrow, lastrow);
        printf("%08hx:  ", i * 16 + offset);
        for (j = 0; j < lastrow; j++) {
            printf("%02x", p[(i * 16) + j]);
            if (j % 2 == 1)
                printf(" ");
        }
        while(j < DUMP_ROWS) {
            printf("  ");
            if (j % 2 == 1)
                printf(" ");
            j++;
        }
        printf("   [ ");
        for (j = 0; j < lastrow; j++) {
            if (isprint(p[(i * 16) + j]))
                printf("%c", p[(i * 16) + j]);
            else
                printf(".");
        }
        while(j < DUMP_ROWS) {
            printf(" ");
            j++;
        }
        printf(" ]\n");
    }
}

void dump_found(char *buf, int key_size, unsigned int block_count, int entropy, int mean) {
  printf("Found at block %u (Entropy is %d%% | Mean Deviation is %d%% = %d%%):\n", block_count * 64, entropy, mean, (entropy + mean) / 2);
  dump_asciihex(buf, key_size, block_count * 64);
  printf("\n");
}

int main(int argc, char *argv[]) {
  int key_size = KEY_SIZE;
  int window_size = 0;
  char *fn;
  FILE *f;
  char *buf;
  int i;
  int reading;
  unsigned int block_count = 0;

  prg = argv[0];

  if (argc < 2 || strcmp(argv[1], "-h") == 0 || strncmp(argv[1], "--h", 3) == 0)
    help();

  while ((i = getopt(argc, argv, "dw:r:k:")) >= 0) {
    switch(i) {
      case 'd':
        debug = 1;
        break;
      case 'w':
        window_size = atoi(optarg);
        break;
      case 'r':
        minimal_randomness = atoi(optarg);
        break;
      case 'k':
        key_size = atoi(optarg);
        break;
      default:
        help();
    }
  }

  if (key_size != KEY_SIZE) {
    if (window_size == 0)
      window_size = (key_size / 10) - 1;
  } else
    window_size = WINDOW_SIZE;
  
  if (key_size < 20 || key_size > 65535 || window_size < 1 || window_size >= key_size || minimal_randomness < 1 || minimal_randomness > 99) {
    fprintf(stderr, "Error: Wrong Values! Limits: 20 < key_size  < 65535; 1 < window_size < key_size; 1 < minimal_randomness < 100\n");
    exit(-1);
  }

  if (key_size < window_size * 8)
    fprintf(stderr, "Warning: The window size is too large, -w should be 1/8 to 1/16 of -k\n");

  if (optind + 1 != argc)
    help();

  fn = argv[argc - 1];

  if ((f = fopen(fn, "r")) == NULL) {
    fprintf(stderr, "Error: Can not open file %s\n", fn);
    exit(-1);
  }
  
  if ((buf = malloc(key_size + window_size)) == NULL) {
    fprintf(stderr, "Error: malloc() failed\n");
    exit(-1);
  }
  memset(buf, 0, key_size + window_size);

  printf("Analyzing %s:\n", fn);
//  if (debug)
    printf("[Key Size: %d byte/%d bit, Window Size: %d byte, Minimal Randomness: %d%%]\n", key_size, key_size * 8, window_size, minimal_randomness);

  minimal_randomness = minimal_randomness * 2;

  if ((reading = fread(buf, 1, key_size, f)) > 0) {
    calculate_randomness(buf, reading);
    if ((ext_entropy + ext_mean) >= minimal_randomness && reading == key_size)
      dump_found(buf, key_size, block_count, ext_entropy, ext_mean);
    if (reading == key_size)
      reading = window_size;
    while (!feof(f) && reading == window_size) {
      if ((reading = fread(buf + key_size, 1, window_size, f)) > 0) {
        ++block_count;
        memmove(buf, buf + reading, key_size);
        calculate_randomness(buf, key_size);
        if ((ext_entropy + ext_mean) >= minimal_randomness)
          dump_found(buf, key_size, block_count, ext_entropy, ext_mean);
      }
    }
  }

  return 0;
}
