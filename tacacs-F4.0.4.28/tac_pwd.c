/*
 * $Id: tac_pwd.c,v 1.15 2006-12-13 01:11:37 heas Exp $
 *
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
 * Copyright (c) 1995-1998 by Cisco systems, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that this
 * copyright and permission notice appear on all copies of the
 * software and supporting documentation, the name of Cisco Systems,
 * Inc. not be used in advertising or publicity pertaining to
 * distribution of the program without specific prior permission, and
 * notice be given in supporting documentation that modification,
 * copying and distribution is by permission of Cisco Systems, Inc.
 *
 * Cisco Systems, Inc. makes no representations about the suitability
 * of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

/* Program to des encrypt a password like Unix.
 * It prompts for the password to encrypt.
 * You can optionally supply a salt to verify a password.
 * Usage: tac_pwd [salt]
 */

#include "tacacs.h"
#include <stdio.h>

/* Forward declarations for modern password hashing functions */
extern char *sha256_hash(const char *password, const char *salt, int rounds);
extern char *sha512_hash(const char *password, const char *salt, int rounds);
extern char *argon2_hash(const char *password, int type, int memory, int time, int parallelism);
extern char *bcrypt_hash(const char *password, int cost);
#ifdef HAVE_STRING_H
# include <string.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#include <time.h>

#if HAVE_MALLOC_H
# include <malloc.h>
#else
# include <stdlib.h>
#endif

#include <errno.h>
#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#define SALTBUFLEN	24
#define HASHBUFLEN	32

void	usage(void);

char *
get_salt(void)
{
    static char buf[SALTBUFLEN];
    char *bp = buf;
    int i, j, r, r1, r2;

    r1 = r2 = 0;
    memset(buf, 0, sizeof(buf));
#if HAVE_RANDOM
    srandom(time(0));
#else
    srand(time(0));
#endif

    /* 4 characters of salt */
    for (j = 0; j <= 1; j++) {
	for (i = 0; i <= 1; i++) {
#if HAVE_RANDOM
	    r = random();
#else
	    r = rand();
#endif
	    r = r & 127;

	    if (r < 46)
		r += 46;

	    if (r > 57 && r < 65)
		r += 7;

	    if (r > 90 && r < 97)
		r += 6;

	    if (r > 122)
		r -= 5;

	    if (i == 0)
		r1 = r;

	    if (i == 1)
		r2 = r;
        }

	snprintf(bp, SALTBUFLEN - (bp - buf), "%c%c", r1, r2);
	bp += 2;
    }
    return buf;
}

char *
do_des(char *passwd, char *salt)
{
    if (salt == NULL)
	salt = get_salt();
    else if (strlen(salt) > 4)
	salt[4] = '\0';

    return crypt(passwd, salt);
}

char *
do_md5(char *passwd, char *salt)
{
    static char hash[HASHBUFLEN];

    if (salt == NULL)
	salt = get_salt();
    if (strlen(salt) > 2)
	salt[2] = '\0';
    snprintf(hash, HASHBUFLEN, "$1$%s$", salt);
    strncpy(hash, crypt(passwd, hash), HASHBUFLEN);

    return hash;
}

char *
do_bcrypt(char *passwd, int cost)
{
    char *hash;
    
#ifdef HAVE_BCRYPT
    if (cost <= 0)
	cost = 12; /* Default cost */
    
    hash = bcrypt_hash(passwd, cost);
    return hash;
#else
    return NULL;
#endif
}

char *
do_argon2(char *passwd, int type, int memory, int time, int parallelism)
{
    char *hash;
    
#ifdef HAVE_LIBSODIUM
    if (memory <= 0) memory = 65536; /* 64MB default */
    if (time <= 0) time = 3; /* 3 iterations default */
    if (parallelism <= 0) parallelism = 4; /* 4 threads default */
    if (type <= 0) type = 1; /* Argon2id default */
    
    hash = argon2_hash(passwd, type, memory, time, parallelism);
    return hash;
#else
    return NULL;
#endif
}

/* PBKDF2 function removed - use Argon2 or bcrypt instead */

char *
do_sha256(char *passwd, char *salt, int rounds)
{
    char *hash;
    
#ifdef HAVE_CRYPT
    if (rounds <= 0)
	rounds = 5000; /* Default rounds */
    
    hash = sha256_hash(passwd, salt, rounds);
    return hash;
#else
    return NULL;
#endif
}

char *
do_sha512(char *passwd, char *salt, int rounds)
{
    char *hash;
    
#ifdef HAVE_CRYPT
    if (rounds <= 0)
	rounds = 5000; /* Default rounds */
    
    hash = sha512_hash(passwd, salt, rounds);
    return hash;
#else
    return NULL;
#endif
}

int
main(int argc, char **argv)
{
    char		*crypt(const char *, const char *);
    char		pass[25],
			*salt = NULL;
    char		*result;
    extern char		*optarg;
    extern int		optind;
    char		*prompt = "Password to be encrypted: ";
    int			opt_e = 0,			/* do not echo passwd*/
			opt_m = 0,			/* create md5 string */
			opt_b = 0,			/* create bcrypt string */
			opt_a = 0,			/* create argon2 string */
			opt_s256 = 0,		/* create sha256 string */
			opt_s512 = 0,		/* create sha512 string */
			n;
    struct termios	t;

    while ((n = getopt(argc, argv, "ehmba:s:256:512:")) != EOF) {
	switch (n) {
	case 'e':
	    opt_e = 1;
	    break;
	case 'h':
	    usage();
	    exit(0);
	    break;
	case 'm':
	    opt_m = 1;
	    break;
	case 'b':
	    opt_b = 1;
	    break;
	case 'a':
	    opt_a = 1;
	    break;
	case 's':
	    if (strcmp(optarg, "256") == 0) {
		opt_s256 = 1;
	    } else if (strcmp(optarg, "512") == 0) {
		opt_s512 = 1;
	    } else {
		usage();
		exit(1);
	    }
	    break;
	default:
	    usage();
	    exit(1);
	}
    }

    if (optind < argc) {
	salt = argv[optind];
    }

    if (opt_e) {
	if (tcgetattr(STDIN_FILENO, &t)) {
	    perror("could not get terminal characteristics");
	    exit(1);
	}
	t.c_lflag &= (~ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }

    write(1, prompt, strlen(prompt));
    n = read(0, pass, sizeof(pass));
    pass[n-1] = '\0';

    if (opt_e) {
	write(1, "\n", strlen("\n"));
	t.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }

    if (opt_m) {
	result = do_md5(pass, salt);
    } else if (opt_b) {
	result = do_bcrypt(pass, 12);
    } else if (opt_a) {
	result = do_argon2(pass, 1, 65536, 3, 4);
    } else if (opt_s256) {
	result = do_sha256(pass, salt, 5000);
    } else if (opt_s512) {
	result = do_sha512(pass, salt, 5000);
    } else {
	result = do_des(pass, salt);
    }
    write(1, result, strlen(result));
    write(1, "\n", 1);

    return(0);
}

void
usage(void)
{
    fprintf(stderr, "Usage: tac_pwd [-ehmba] [-s 256|512] [<salt>]\n");
    fprintf(stderr, "\t-e\tdo not echo the password\n"
		    "\t-h\tdisplay this message\n"
		    "\t-m\tgenerate MD5 crypt\n"
		    "\t-b\tgenerate bcrypt hash\n"
		    "\t-a\tgenerate Argon2 hash\n"
		    "\t-s 256\tgenerate SHA-256 crypt\n"
		    "\t-s 512\tgenerate SHA-512 crypt\n");

    return;
}
