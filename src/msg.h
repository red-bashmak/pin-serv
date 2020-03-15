#pragma once

#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>

enum fields
{
    PIN = 1,
    PAN = 2,
    BLOCK = 4,
    KEY = 8,
    TOKEN = 16
};

enum commands
{
    PIN_BLOCK,
    BATCH,
    NEW_KEY,
    CHECK
};

#define PIN_FS 2
#define PAN_FS 8
#define BLOCK_FS 8
#define KEY_FS 24
#define TOKEN_FS 8

typedef struct _msg
{
    uint16_t size;
    uint8_t field_flags : 6;
    uint8_t command : 2;
    uint8_t payload[];
} msg;

typedef struct _pin_block_args
{
    uint8_t pin[PIN_FS];
    uint8_t pan[PAN_FS];
} pin_block_args;

typedef struct _check_args
{
    uint8_t pin[PIN_FS];
    uint8_t pan[PAN_FS];
    uint8_t block[BLOCK_FS];
} check_args;

typedef struct _new_key_args
{
    uint8_t new_key[KEY_FS];
    uint8_t token[TOKEN_FS];
} new_key_args;

msg *msg_create(void);
msg *msg_wrap_payload(uint8_t field_flags, uint8_t command, uint8_t *payload, size_t payload_size);
msg *msg_decode(uint8_t *buff /*, size_t buff_size*/);
void msg_free(msg *m);
bool has_only_flags(msg * m, uint8_t flags);
check_args *get_check_args(msg *m);
new_key_args *get_new_key_args(msg *m);
pin_block_args *get_pin_block_args(msg *m);
char *msg_to_string(msg *msg);