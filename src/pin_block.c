#include "hex_codec.h"
#include "pin_block.h"
#include <arpa/inet.h>

static void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

pb_crypto *pb_crypto_new()
{
  pb_crypto *result = malloc(sizeof(*result));
  if (result == NULL)
  {
    perror("pb_crypto_new()");
    exit(1);
  }

  result->codec = hex_codec_new();
  result->cipher = EVP_des_ede_cbc();
  int key_length = EVP_CIPHER_key_length(result->cipher);
  int iv_length = EVP_CIPHER_iv_length(result->cipher);

  result->key = malloc(sizeof(uint8_t) * (key_length));
  result->key_length = key_length;
  memset(result->key, 0, key_length);
  result->iv = malloc(sizeof(uint8_t) * iv_length);
  memset(result->iv, 0, iv_length);
  if (result->key == NULL || result->iv == NULL)
  {
    perror("pin_block_enc_new() key iv");
    exit(1);
  }

  EVP_CIPHER_CTX *ctx;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0))
    handleErrors();

  result->ctx = ctx;

  return result;
}

void pb_crypto_set_key_from_file(pb_crypto *self, const char *file_path)
{
  FILE *key_file;
  if ((key_file = fopen(file_path, "r")) == NULL)
  {
    perror("Cannot open key file, read_key_from_file()");
    exit(1);
  }

  char buff[self->key_length * 2 + 1];
  while (!feof(key_file))
  {
    if (fgets(buff, self->key_length * 2 + 1, key_file))
    {
      size_t hex_key_len = strlen(buff);
      hex_codec_decode(self->codec, (const char *)buff, hex_key_len, (uint8_t *)self->key);
    }
  }

  fclose(key_file);
}

void pb_crypto_free(pb_crypto *self)
{
  hex_codec_free(self->codec);
  memset(self->key, 0, self->key_length);
  self->key_length = 0;
  free(self->key);
  free(self->iv);
  // free(self->cipher);
  EVP_CIPHER_CTX_free(self->ctx);
  free(self);
}

inline static long long htonll(long long x)
{
  return ((((long long)htonl(x)) << 32) + htonl((x) >> 32));
}

static void create_pin_block(pin_block *result, const uint8_t *pan, const uint8_t *pin)
{
  long long pin_part, pan_part;
  pin_part = ((4L << 56) | ((long long)pin[0] << 48) | ((long long)pin[1] << 40)) ^ 0x000000FFFFFFFFFFL;
  pan_part = (htonll(*((long long *)pan)) >> 4) & 0x0000FFFFFFFFFFFFL;

  result->block = htonll(pin_part ^ pan_part);
}

static int encrypt_pin_block(pb_crypto *self, pin_block *raw, pin_block *result)
{
  unsigned char tmpbuff[BLOCK_BUFFER_SIZE * 2];

  int len = 0;

  if (1 != EVP_EncryptInit_ex(self->ctx, self->cipher, NULL, self->key, self->iv))
    handleErrors();

  if (1 != EVP_EncryptUpdate(self->ctx, tmpbuff, &len, raw->buff, BLOCK_BUFFER_SIZE))
    handleErrors();

  if (1 != EVP_EncryptFinal_ex(self->ctx, tmpbuff + len, &len))
    handleErrors();

  if (len < BLOCK_BUFFER_SIZE)
  {
    perror("pin_block_enc_make_encrypted_pin_block, enc error");
    exit(1);
  }
  else
  {
    memcpy(result, tmpbuff, BLOCK_BUFFER_SIZE);
    return len;
  }
}

static int check_luhn(const char *pPurported)
{
  int nSum = 0;
  int nDigits = strlen(pPurported);
  
  int nParity = (nDigits - 1) % 2;
  char cDigit[2] = "\0";
  for (int i = nDigits; i > 0; i--)
  {
    cDigit[0] = pPurported[i - 1];
    int nDigit = atoi(cDigit);

    if (nParity == i % 2)
      nDigit = nDigit * 2;

    nSum += nDigit / 10;
    nSum += nDigit % 10;
  }
  return 0 == nSum % 10;
}

pin_block *pb_crypto_make_encrypted_pin_block(pb_crypto *self, const pin_block_args *args)
{
  char pan_hex[PAN_FS*2 + 1] = {0};
  hex_codec_encode(self->codec, args->pan, PAN_FS, pan_hex);
  if(check_luhn(pan_hex)){
  pin_block *result = malloc(sizeof(*result));
  if (result == NULL)
  {
    perror("pb_crypto_make_encrypted_pin_block()");
    exit(1);
  }

  create_pin_block(result, args->pan, args->pin);
  encrypt_pin_block(self, result, result);

  return result;
  } else
  {
    printf("\033[1;31m[error]\033[0m: bad pan\n");
    exit(1);
  }
  
}

pin_block *pb_crypto_make_pin_block(pb_crypto *self, const pin_block_args *args)
{
  pin_block *result = malloc(sizeof(*result));
  if (result == NULL)
  {
    perror("pb_crypto_make_encrypted_pin_block()");
    exit(1);
  }

  create_pin_block(result, args->pan, args->pan);

  return result;
}

bool pb_crypto_check_pin_block(pb_crypto *sefl, const check_args *args)
{
  pin_block from_args;

  create_pin_block(&from_args, args->pan, args->pin);
  encrypt_pin_block(sefl,&from_args, &from_args);

  return from_args.block == *((long long*)args->block);
}