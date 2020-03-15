#pragma once
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "msg.h"

#define BLOCK_BUFFER_SIZE 8


typedef struct _pin_block_encryptor
{
  uint8_t *key;
  size_t key_length;
  uint8_t *iv;
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *cipher;
  hex_codec *codec;
} pb_crypto;

typedef union _pin_block {
  long long block;
  uint8_t buff[BLOCK_BUFFER_SIZE];
} pin_block;

pb_crypto* pb_crypto_new();
void pb_crypto_set_key_from_file(pb_crypto* self, const char* file_path);
void pb_crypto_free(pb_crypto* self);

pin_block* pb_crypto_make_encrypted_pin_block(pb_crypto* self, const pin_block_args* args);
pin_block* pb_crypto_make_pin_block(pb_crypto* self, const pin_block_args* args);

bool pb_crypto_check_pin_block(pb_crypto * sefl, const check_args * args);
