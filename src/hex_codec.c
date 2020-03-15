#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "hex_codec.h"

char hex_symbols[ENCODING_TABLE_SIZE] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

hex_codec *hex_codec_new()
{
  hex_codec *result = malloc(sizeof(*result));
  if (result == NULL)
  {
    perror("hex_codec_new() ");
    exit(1);
  }

  memcpy(result->encoding_table, &hex_symbols, ENCODING_TABLE_SIZE);
  memset(result->decoding_table, 0xff, DECODING_TABLE_SIZE);

  for (int i = 0; i < ENCODING_TABLE_SIZE; i++)
  {
    result->decoding_table[(int)result->encoding_table[i]] = i;
  }

  result->decoding_table['A'] = result->decoding_table['a'];
  result->decoding_table['B'] = result->decoding_table['b'];
  result->decoding_table['C'] = result->decoding_table['c'];
  result->decoding_table['D'] = result->decoding_table['d'];
  result->decoding_table['E'] = result->decoding_table['e'];
  result->decoding_table['F'] = result->decoding_table['f'];

  result->initialized = true;

  return result;
}

void hex_codec_print_decoding_table(hex_codec *self)
{
  printf("\n");
  for (int i = 0; i < DECODING_TABLE_SIZE; i++)
  {
    printf(
        "[%03d] - '%c' in table [%3d] - '%c'\n",
        i,
        isgraph(i) ? i : '.',
        self->decoding_table[i],
        isgraph(self->decoding_table[i]) ? self->decoding_table[i] : '.');
  }
  printf("\n");
}

size_t hex_codec_decode(hex_codec *self, const char *hex, size_t hex_size, uint8_t *bin_target)
{
  if ((hex_size & 1) != 0)
  {
    fprintf(stderr, "error: badsized hex string [%s]\n", hex);
    return -1;
  }
  else
  {
    for (int i = 0; i < hex_size; i += 2)
    {
      uint8_t decoded = (self->decoding_table[(int)hex[i]] << 4) | self->decoding_table[(int)hex[i+1]];
      if (decoded < 0)
      {
        fprintf(stderr, "error: decoding fail on hex string [%s]\n", hex);
        return -1;
      }
      *(bin_target++) = decoded;
    }
    return hex_size / 2;
  }
}

size_t hex_codec_encode(hex_codec *self, const uint8_t *binary, size_t binary_size, char *target)
{
  for (int i = 0; i < binary_size; i++)
  {
    int v = binary[i] & 0xff;
    *(target++) = self->encoding_table[(v >> 4)];
    *(target++) = self->encoding_table[(v & 0xf)];
  }
  
  return binary_size * 2;
}

void hex_codec_free(hex_codec *self)
{
  self->initialized = false;
  free(self);
}