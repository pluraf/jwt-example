/* SPDX-License-Identifier: MIT */

/*
Copyright (c) 2024 Pluraf Embedded AB <code@pluraf.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to
do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
*/


#include <stdio.h>
#include <stdlib.h>
#include <openssl/types.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "jwt.h"


point_t * read_public_key(const char *pem_file) {
    FILE *file = fopen(pem_file, "r");
    if (! file) {
        perror("Unable to open PEM file");
        return NULL;
    }

    // Read the EC public key from the PEM file
    EVP_PKEY *pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);

    if (! pkey) {
        fprintf(stderr, "Error reading public key from PEM file.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Ensure the key is an EC key
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        fprintf(stderr, "The public key is not an EC key.\n");
        EVP_PKEY_free(pkey);
        return NULL;
    }

    // Extract the EC key and get the public point
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(ec_key);

    // Allocate memory for the x and y coordinates
    BIGNUM * x = BN_new();
    BIGNUM * y = BN_new();

    // Extract the x and y coordinates of the public key
    if (! EC_POINT_get_affine_coordinates_GFp(group, pub_key_point, x, y, NULL)) {
        fprintf(stderr, "Error extracting the affine coordinates.\n");
        BN_free(x);
        BN_free(y);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    unsigned char *pub_point_x = (unsigned char *)malloc(BN_num_bytes(x));
    unsigned char *pub_point_y = (unsigned char *)malloc(BN_num_bytes(y));

    BN_bn2bin(x, pub_point_x);
    BN_bn2bin(y, pub_point_y);

    point_t * key = calloc(1, sizeof(point_t));
    NN_Decode(key->x, NUMWORDS - 1, pub_point_x, NUMBYTES - NN_DIGIT_LEN);
    NN_Decode(key->y, NUMWORDS - 1, pub_point_y, NUMBYTES - NN_DIGIT_LEN);

    // Free memory
    free(pub_point_x);
    free(pub_point_y);
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);

    return key;
}


NN_DIGIT * read_private_key(const char *filename) {
    FILE *fp = fopen(filename, "r");

    if (fp == NULL) {
        perror("Unable to open PEM file");
        return NULL;
    }

    // Load the private key from the PEM file
    EC_KEY * ec_key =  PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (ec_key == NULL) {
        fprintf(stderr, "Error reading EC private key from PEM file\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    const BIGNUM *priv_key = EC_KEY_get0_private_key(ec_key);
    if (priv_key == NULL) {
        return NULL;
    }

    int num_bytes = BN_num_bytes(priv_key);
    unsigned char *priv_key_bytes = (unsigned char *)malloc(num_bytes);
    BN_bn2bin(priv_key, priv_key_bytes);
    NN_DIGIT * key = (NN_DIGIT *)calloc(1, num_bytes);
    NN_Decode(key, NUMWORDS - 1, priv_key_bytes, NUMBYTES - NN_DIGIT_LEN);

    // Free memory
    free(priv_key_bytes);
    EC_KEY_free(ec_key);

    return key;
}

int main() {
    char * project_id = "project";
    int time = 10;
    int jwt_exp_secs = 20;

    ecc_init();

    NN_DIGIT * private_key = read_private_key("../bits/private_key.pem");
    char * jwt = jwt_create(project_id, time, private_key, jwt_exp_secs);
    printf("JWT: %s\n", jwt);
    point_t * public_key = read_public_key("../bits/public_key.pem");
    printf("verification: %d\n", jwt_verify(jwt, public_key));
}