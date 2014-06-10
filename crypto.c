/*
 *  Cryptographic routines for faifa using standalone SHA2
 *
 *  Copyright (C) 2008 Florian Fainelli <florian@openwrt.org>
 *
 *  The BSD License
 *  ===============
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the name of OpenLink Software Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL OPENLINK OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "crypto.h"
#include "sha2.h"

#define HASH_SIZ	SHA256_DIGEST_LENGTH

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

		memcpy(secret->value, isecret, l);
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
	memset(hash_value, 0, sizeof(hash_value));

	init_salted_secret(&secret, isecret, salt);
	SHA256_Update(&context, secret.value, secret.len);
	SHA256_Final(hash_value, &context);

	/* Do it 998 times as the standard requires it
	* or only 4 times if we use the NID */
	for(i = 0; i < max; i++) {
		SHA256_Init(&context);
		SHA256_Update(&context, hash_value, HASH_SIZ);
		SHA256_Final(hash_value, &context);
	}

	return hash_value;
}

int gen_passphrase(const char *password, u_int8_t *key, const unsigned char *salt)
{
	u_int8_t password_cpy[MAX_SECRET_SIZ + 1];
	const unsigned char *password_hash;

	/* Use a local variable to store the input password */
	memcpy(password_cpy, password, MAX_SECRET_SIZ);

	password_hash = hash_hpav(password_cpy, salt);
	memcpy(key, password_hash, 16);

	return 0;
}
