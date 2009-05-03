/*
 *  Cryptographic routines for faifa using OpenSSL
 *
 *  Copyright (C) 2008 Florian Fainelli <florian@openwrt.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>

#include "crypto.h"

#define HASH_SIZ	32

unsigned char hash_value[HASH_SIZ];

u_int8_t dak_salt[SALT_SIZ] = {0x08, 0x85, 0x6D, 0xAF, 0x7C, 0xF5, 0x81, 0x85};
u_int8_t nmk_salt[SALT_SIZ] = {0x08, 0x85, 0x6D, 0xAF, 0x7C, 0xF5, 0x81, 0x86};


/**
 * init_salted_secret - initialise a secret using a salt
 * @secret:	secret to initialise will be modified
 * @isecret:	initialisation secret
 * @salt:	secret to initialise with
 */
void init_salted_secret(struct salted_secret *secret, const unsigned char *isecret, const unsigned char *isalt)
{
	unsigned char l = ' ';

	secret->len = 0;
	memset(secret->value, 0, sizeof(secret->value));

	if (isecret) {
		l = (unsigned char)strlen((char *)isecret);
		if (l > MAX_SECRET_SIZ)
			l = MAX_SECRET_SIZ;

		memcpy(secret->value, (unsigned char *)isecret, l);
	}
	
	if (!isalt)
		l = 16;

	secret->len = (unsigned char) (secret->len + l);

	if (isalt) {
		memcpy(&secret->value[secret->len], (unsigned char*)isalt, SALT_SIZ);
		secret->len += SALT_SIZ;
	}
}

/**
 * hash_hpav - hash a secret with a salt as HomePlug AV requires it
 * @isecret:	initialisation secret
 * @salt:	salt to initialise the secret with
 */
const unsigned char* hash_hpav(const unsigned char* isecret, const unsigned char *salt)
{
	SHA256_CTX context;
	struct salted_secret secret;
	int i, max;

	/* Null salt is the NetworkID */
	if (!salt)
		max = 4;
	else
		max = 999;

	SHA256_Init(&context);
	memset(hash_value, 0x00, sizeof(hash_value));

	init_salted_secret(&secret, isecret, salt);
	SHA256_Update(&context, secret.value, secret.len);
	SHA256_Final(NULL, &context);

	/* Do it 998 times as the standard requires it 
	* or only 4 times if we use the NID */
	for(i = 0; i < max; i++) {
		SHA256_Init(&context);
		SHA256_Update(&context, hash_value, HASH_SIZ);
		SHA256_Final(NULL, &context);
	}

	return hash_value;
}

int gen_passphrase(const short unsigned int *password, u_int8_t *key, const unsigned char *salt)
{
	unsigned char password_cpy[MAX_SECRET_SIZ + 1];
	const unsigned char *password_hash;

	/* Use a local variable to tore the input password */
	memcpy((unsigned char *)password_cpy, password, MAX_SECRET_SIZ);

	password_hash = (const unsigned char *)malloc(HASH_SIZ);
	if (!password_hash) {
		perror("malloc");
		return -1;
	}

	password_hash = hash_hpav(password_cpy, salt);
	memcpy(key, password_hash, 16);

	return 0;
}
