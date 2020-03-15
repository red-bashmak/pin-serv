#include "msg.h"
#include "hex_codec.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SET_BIT(VAL, N) (VAL |= (1U << N))
#define CLR_BIT(VAL, N) (VAL &= ~(1U << N))
#define IS_SET(VAL, N) (!!(VAL & (1U << N)))
#define MSG_HEADER_OFFSET 2


const size_t field_sizes[] = {
    [PIN] = PIN_FS,
    [PAN] = PAN_FS,
    [BLOCK] = BLOCK_FS,
    [KEY] = KEY_FS,
    [TOKEN] = TOKEN_FS};

static size_t get_field_size(uint8_t field_flags)
{
    size_t result = 0;
    for (int f = PIN; f <= TOKEN; f <<= 1)
    {
        result += (field_flags & f) ? field_sizes[f] : 0;
    }
    return result;
}

static bool check_payload(uint8_t field_flags, size_t payload_size)
{
    return payload_size % get_field_size(field_flags);
}

static uint16_t decode_msg_size(uint8_t *in)
{
    return *(in) << 8 | *(in + 1);
}

msg *msg_create()
{
    msg *result = malloc(sizeof(*result));
    if (result == NULL)
    {
        perror("msg_create()");
        exit(1);
    }

    result->command = PIN_BLOCK;
    result->field_flags = 0;
    result->size = 0;
    // result

    return result;
}

msg *msg_wrap_payload(uint8_t field_flags, uint8_t command, uint8_t *payload, size_t payload_size)
{
    if (check_payload(field_flags, payload_size))
    {
        msg *r = msg_create();
        r->field_flags = field_flags;
        r->command = command;
        r->size = payload_size + 1;
        memcpy(r->payload, payload, payload_size);
        return r;
    }
    else
    {
        perror("msg_wrap_payload(): bad payload");
        exit(1);
    }
}

msg *msg_decode(uint8_t *buff /*, size_t buff_size*/)
{
    size_t msg_size = decode_msg_size(buff);

    assert(msg_size > 3);

    msg *r = (msg *)malloc(sizeof(*r) + sizeof(uint8_t) * msg_size);
    if (r == NULL)
    {
        perror("msg_decode(): No memory to allocate msg");
        exit(1);
    }

    r->size = msg_size;
    void *addr = (void *)r + MSG_HEADER_OFFSET;
    memcpy(addr, buff + MSG_HEADER_OFFSET, r->size);

    return r;
}

void msg_free(msg *m)
{
    if (m != NULL)
    {
        if (m->payload != NULL)
        {
            // free(m->payload);
        }
        free(m);
    }
}

bool has_only_flags(msg * m, uint8_t flags){
    return !(m->field_flags ^ flags);
}

static inline void *get_args(msg *m)
{
    void *r = malloc(get_field_size(m->field_flags));
    if (r == NULL)
    {
        perror("get_args(): no allocate check_args");
        exit(1);
    }
    memcpy(r, m->payload, m->size - 1);
    return r;
}

check_args *get_check_args(msg *m)
{
    if (m->command == CHECK && has_only_flags(m, PIN | PAN | BLOCK))
    {
        return (check_args *)get_args(m);
    }
    else
    {
        perror("Bad message for CHECK command");
        exit(1);
    }
}

new_key_args *get_new_key_args(msg *m)
{
    if (m->command == NEW_KEY && has_only_flags(m, KEY | TOKEN))
    {
        return (new_key_args *)get_args(m);
    }
    else
    {
        perror("Bad message for NEW_KEY command");
        exit(1);
    }
}

pin_block_args *get_pin_block_args(msg *m)
{

    if (m->command == PIN_BLOCK && has_only_flags(m, PIN | PAN))
    {
        return (pin_block_args *)get_args(m);
    }
    else
    {
        perror("Bad message for PIN_BLOCK command");
        exit(1);
    }
}

static const char *field_names[] = {
    [PIN] = "PIN",
    [PAN] = "PAN",
    [BLOCK] = "BLOCK",
    [KEY] = "KEY",
    [TOKEN] = "TOKEN"};

static void fields(uint8_t field_flags, char *buff)
{
    for (int f = PIN; f <= TOKEN; f <<= 1)
    {
        if (field_flags & f)
        {
            strcat(buff, field_names[f]);
            strcat(buff, ", ");
        }
    }
    int last = strlen(buff);
    buff[last - 2] = 0;
}

char *msg_to_string(msg *m)
{
    char *result = (char *)calloc(128, sizeof(char));
    char f_names[20] = {0};
    fields(m->field_flags, f_names);
    switch (m->command)
    {
    case PIN_BLOCK:
        sprintf(result, "msg{PIN_BLOCK, size=%d, fields=%s}", m->size, f_names);
        break;

    case BATCH:
        sprintf(result, "msg{BATCH, size=%d, fields=%s}", m->size, f_names);
        break;

    case NEW_KEY:
        sprintf(result, "msg{NEW_KEY, size=%d, fields=%s}", m->size, f_names);
        break;

    case CHECK:
        sprintf(result, "msg{CHECK, size=%d, fields=%s}", m->size, f_names);
        break;

    default:
        break;
    }
    return result;
}