/*
 * $Id: modern_crypto.c,v 1.1 2024-01-01 00:00:00 tac_plus Exp $
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

/*
 * modern_crypto.c - Modern cryptographic functions for RFC 8907 compliance
 * and modern password hashing
 */

#include "config.h"
#include "tacacs.h"
#include "tac_plus.h"

#ifdef HAVE_LIBSODIUM
# include <sodium.h>
#endif

#ifdef HAVE_BCRYPT
/* Using system crypt() for bcrypt - no separate header needed */
#endif

/* OpenSSL removed - using libsodium and system crypt() instead */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif

/* ===== Modern Password Hashing Functions ===== */

#ifdef HAVE_BCRYPT
/*
 * bcrypt password verification using system crypt()
 */
int
bcrypt_verify(const char *password, const char *hash)
{
    char *result;
    
    if (!password || !hash) {
        return 0;
    }
    
    result = crypt(password, hash);
    return (result && strcmp(result, hash) == 0) ? 1 : 0;
}

/*
 * bcrypt password hashing using system crypt()
 */
char *
bcrypt_hash(const char *password, int cost)
{
    char *hash;
    char salt[64];
    char *result;
    int i;
    
    if (!password) {
        return NULL;
    }
    
    /* Generate a random salt for bcrypt */
    snprintf(salt, sizeof(salt), "$2b$%02d$", cost);
    
    /* Add random characters for the salt */
    for (i = 0; i < 22; i++) {
        salt[7 + i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"[rand() % 64];
    }
    salt[29] = '\0';
    
    result = crypt(password, salt);
    if (!result) {
        return NULL;
    }
    
    hash = malloc(strlen(result) + 1);
    if (!hash) {
        return NULL;
    }
    
    strcpy(hash, result);
    return hash;
}
#else
/* Stub functions when bcrypt is not available */
int
bcrypt_verify(const char *password, const char *hash)
{
    return 0;
}

char *
bcrypt_hash(const char *password, int cost)
{
    return NULL;
}
#endif /* HAVE_BCRYPT */

#ifdef HAVE_LIBSODIUM
/*
 * Argon2 password verification using libsodium
 */
int
argon2_verify(const char *password, const char *hash)
{
    if (!password || !hash) {
        return 0;
    }
    
    /* Use libsodium's crypto_pwhash_str_verify for verification */
    return (crypto_pwhash_str_verify(hash, password, strlen(password)) == 0) ? 1 : 0;
}

/*
 * Argon2 password hashing using libsodium
 */
char *
argon2_hash(const char *password, int type, int memory, int time, int parallelism)
{
    char *hash;
    int ret;
    
    if (!password) {
        return NULL;
    }
    
    /* Allocate memory for the hash string */
    hash = malloc(crypto_pwhash_STRBYTES);
    if (!hash) {
        return NULL;
    }
    
    /* Use libsodium's crypto_pwhash_str for hashing */
    /* Note: libsodium uses different parameter names and defaults */
    /* memory: memory cost (in bytes), time: time cost (iterations), parallelism: threads */
    ret = crypto_pwhash_str(hash, password, strlen(password), 
                           time, memory);
    
    if (ret != 0) {
        free(hash);
        return NULL;
    }
    
    return hash;
}
#else
/* Stub functions when libsodium is not available */
int
argon2_verify(const char *password, const char *hash)
{
    return 0;
}

char *
argon2_hash(const char *password, int type, int memory, int time, int parallelism)
{
    return NULL;
}
#endif /* HAVE_LIBSODIUM */

/* PBKDF2 functions removed - use Argon2 or bcrypt instead */

#ifdef HAVE_CRYPT
/*
 * SHA-256 password verification (crypt-style)
 */
int
sha256_verify(const char *password, const char *hash)
{
    char *crypt_hash;
    
    if (!password || !hash) {
        return 0;
    }
    
    crypt_hash = crypt(password, hash);
    if (!crypt_hash) {
        return 0;
    }
    
    return (strcmp(crypt_hash, hash) == 0) ? 1 : 0;
}

/*
 * SHA-256 password hashing (crypt-style)
 */
char *
sha256_hash(const char *password, const char *salt, int rounds)
{
    char salt_str[32];
    
    if (!password) {
        return NULL;
    }
    
    if (!salt) {
        /* Generate random salt */
        srand(time(NULL));
        for (int i = 0; i < 16; i++) {
            salt_str[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"[rand() % 64];
        }
        salt_str[16] = '\0';
        salt = salt_str;
    }
    
    /* Format: $5$rounds=5000$salt$hash */
    char *format = malloc(strlen("$5$rounds=") + 10 + strlen(salt) + 10);
    if (!format) {
        return NULL;
    }
    
    sprintf(format, "$5$rounds=%d$%s", rounds, salt);
    
    char *result = crypt(password, format);
    free(format);
    
    return result ? strdup(result) : NULL;
}

/*
 * SHA-512 password verification (crypt-style)
 */
int
sha512_verify(const char *password, const char *hash)
{
    char *crypt_hash;
    
    if (!password || !hash) {
        return 0;
    }
    
    crypt_hash = crypt(password, hash);
    if (!crypt_hash) {
        return 0;
    }
    
    return (strcmp(crypt_hash, hash) == 0) ? 1 : 0;
}

/*
 * SHA-512 password hashing (crypt-style)
 */
char *
sha512_hash(const char *password, const char *salt, int rounds)
{
    char salt_str[32];
    
    if (!password) {
        return NULL;
    }
    
    if (!salt) {
        /* Generate random salt */
        srand(time(NULL));
        for (int i = 0; i < 16; i++) {
            salt_str[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"[rand() % 64];
        }
        salt_str[16] = '\0';
        salt = salt_str;
    }
    
    /* Format: $6$rounds=5000$salt$hash */
    char *format = malloc(strlen("$6$rounds=") + 10 + strlen(salt) + 10);
    if (!format) {
        return NULL;
    }
    
    sprintf(format, "$6$rounds=%d$%s", rounds, salt);
    
    char *result = crypt(password, format);
    free(format);
    
    return result ? strdup(result) : NULL;
}
#else
/* Stub functions when crypt is not available */
int
sha256_verify(const char *password, const char *hash)
{
    return 0;
}

char *
sha256_hash(const char *password, const char *salt, int rounds)
{
    return NULL;
}

int
sha512_verify(const char *password, const char *hash)
{
    return 0;
}

char *
sha512_hash(const char *password, const char *salt, int rounds)
{
    return NULL;
}
#endif /* HAVE_CRYPT */

/* ===== Modern Hash Algorithms for RFC 8907 ===== */

#ifdef HAVE_LIBSODIUM
/*
 * Create SHA-256 hash for packet encryption using libsodium
 */
int
create_sha256_hash(int session_id, char *key, u_char version, u_char seq_no,
                   u_char *prev_hash, u_char *hash)
{
    crypto_hash_sha256_state state;
    u_char *md_stream;
    int md_len;
    u_char *mdp;
    
    if (!key || !hash) {
        return 0;
    }
    
    md_len = strlen(key) + 4; /* key + session_id + version + seq_no */
    if (prev_hash) {
        md_len += TAC_SHA256_DIGEST_LEN;
    }
    
    md_stream = malloc(md_len);
    if (!md_stream) {
        return 0;
    }
    
    mdp = md_stream;
    memcpy(mdp, key, strlen(key));
    mdp += strlen(key);
    *mdp++ = (session_id >> 24) & 0xff;
    *mdp++ = (session_id >> 16) & 0xff;
    *mdp++ = (session_id >> 8) & 0xff;
    *mdp++ = session_id & 0xff;
    *mdp++ = version;
    *mdp++ = seq_no;
    
    if (prev_hash) {
        memcpy(mdp, prev_hash, TAC_SHA256_DIGEST_LEN);
        mdp += TAC_SHA256_DIGEST_LEN;
    }
    
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, md_stream, md_len);
    crypto_hash_sha256_final(&state, hash);
    
    free(md_stream);
    return 1;
}

/*
 * Create SHA-512 hash for packet encryption using libsodium
 */
int
create_sha512_hash(int session_id, char *key, u_char version, u_char seq_no,
                   u_char *prev_hash, u_char *hash)
{
    crypto_hash_sha512_state state;
    u_char *md_stream;
    int md_len;
    u_char *mdp;
    
    if (!key || !hash) {
        return 0;
    }
    
    md_len = strlen(key) + 4; /* key + session_id + version + seq_no */
    if (prev_hash) {
        md_len += TAC_SHA512_DIGEST_LEN;
    }
    
    md_stream = malloc(md_len);
    if (!md_stream) {
        return 0;
    }
    
    mdp = md_stream;
    memcpy(mdp, key, strlen(key));
    mdp += strlen(key);
    *mdp++ = (session_id >> 24) & 0xff;
    *mdp++ = (session_id >> 16) & 0xff;
    *mdp++ = (session_id >> 8) & 0xff;
    *mdp++ = session_id & 0xff;
    *mdp++ = version;
    *mdp++ = seq_no;
    
    if (prev_hash) {
        memcpy(mdp, prev_hash, TAC_SHA512_DIGEST_LEN);
        mdp += TAC_SHA512_DIGEST_LEN;
    }
    
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, md_stream, md_len);
    crypto_hash_sha512_final(&state, hash);
    
    free(md_stream);
    return 1;
}

/*
 * SHA-256 XOR encryption (similar to md5_xor)
 * Only needed by tac_plus daemon, not tac_pwd
 */
#ifndef TAC_PWD_ONLY
int
sha256_xor(HDR *hdr, u_char *data, char *key)
{
    u_char hash[TAC_SHA256_DIGEST_LEN];
    u_char last_hash[TAC_SHA256_DIGEST_LEN];
    u_char *prev_hashp = NULL;
    int data_len, i, k;
    
    if (!hdr || !data || !key) {
        return 0;
    }
    
    data_len = ntohl(hdr->datalength);
    
    for (i = 0; i < data_len; i += TAC_SHA256_DIGEST_LEN) {
        create_sha256_hash(ntohl(hdr->session_id), key, hdr->version, hdr->seq_no, prev_hashp, hash);
        
        if (debug & DEBUG_MD5_HASH_FLAG) {
            report(LOG_DEBUG, "SHA256 hash for session %d, version %d, seq %d:",
                   ntohl(hdr->session_id), hdr->version, hdr->seq_no);
            for (k = 0; k < TAC_SHA256_DIGEST_LEN; k++) {
                report(LOG_DEBUG, " %02x", hash[k]);
            }
            report(LOG_DEBUG, "\n");
        }
        
        for (k = 0; k < TAC_SHA256_DIGEST_LEN && (i + k) < data_len; k++) {
            data[i + k] ^= hash[k];
        }
        
        memcpy(last_hash, hash, TAC_SHA256_DIGEST_LEN);
        prev_hashp = last_hash;
    }
    
    return 1;
}
#endif /* !TAC_PWD_ONLY */

/*
 * SHA-512 XOR encryption (similar to md5_xor)
 * Only needed by tac_plus daemon, not tac_pwd
 */
#ifndef TAC_PWD_ONLY
int
sha512_xor(HDR *hdr, u_char *data, char *key)
{
    u_char hash[TAC_SHA512_DIGEST_LEN];
    u_char last_hash[TAC_SHA512_DIGEST_LEN];
    u_char *prev_hashp = NULL;
    int data_len, i, k;
    
    if (!hdr || !data || !key) {
        return 0;
    }
    
    data_len = ntohl(hdr->datalength);
    
    for (i = 0; i < data_len; i += TAC_SHA512_DIGEST_LEN) {
        create_sha512_hash(ntohl(hdr->session_id), key, hdr->version, hdr->seq_no, prev_hashp, hash);
        
        if (debug & DEBUG_MD5_HASH_FLAG) {
            report(LOG_DEBUG, "SHA512 hash for session %d, version %d, seq %d:",
                   ntohl(hdr->session_id), hdr->version, hdr->seq_no);
            for (k = 0; k < TAC_SHA512_DIGEST_LEN; k++) {
                report(LOG_DEBUG, " %02x", hash[k]);
            }
            report(LOG_DEBUG, "\n");
        }
        
        for (k = 0; k < TAC_SHA512_DIGEST_LEN && (i + k) < data_len; k++) {
            data[i + k] ^= hash[k];
        }
        
        memcpy(last_hash, hash, TAC_SHA512_DIGEST_LEN);
        prev_hashp = last_hash;
    }
    
    return 1;
}
#endif /* !TAC_PWD_ONLY */

#else
/* Stub functions when libsodium is not available */
int
create_sha256_hash(int session_id, char *key, u_char version, u_char seq_no,
                   u_char *prev_hash, u_char *hash)
{
    return 0;
}

int
create_sha512_hash(int session_id, char *key, u_char version, u_char seq_no,
                   u_char *prev_hash, u_char *hash)
{
    return 0;
}

int
sha256_xor(HDR *hdr, u_char *data, char *key)
{
    return 0;
}

int
sha512_xor(HDR *hdr, u_char *data, char *key)
{
    return 0;
}
#endif /* HAVE_LIBSODIUM */
