#pragma once

#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>

#define DECODING_TABLE_SIZE 128
#define ENCODING_TABLE_SIZE 16

typedef struct _hex_codec
{
  bool initialized;
  char encoding_table[ENCODING_TABLE_SIZE];
  char decoding_table[DECODING_TABLE_SIZE];
} hex_codec;


hex_codec*  hex_codec_new();
void        hex_codec_print_decoding_table(hex_codec* self);
size_t      hex_codec_decode(hex_codec* self, const char* hex, size_t hex_size, uint8_t * bin_target);
size_t      hex_codec_encode(hex_codec* self, const uint8_t* binary, size_t binary_size, char *target);

void        hex_codec_free(hex_codec* self);


/*
void print_table_dec();
void initialiseDecodingTable();
int hex2bin(const char *src, char *target);
int bin2hex(const char *src, char *target);
*/