#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "hex_codec.h"
#include "msg.h"
#include "pin_block.h"

#define PORT 7000

uv_loop_t *loop;

int total_read;
int total_written;

typedef struct
{
  uv_write_t req;
  uv_buf_t buf;
} write_req_t;

//////////////////////////////////////////////////////////////////////////////////////////

typedef struct node
{
  char *data;
  struct node *next;
} strs;

strs *create_item(const char *data, int data_length)
{
  strs *result = malloc(sizeof(struct node));
  result->data = malloc(sizeof(char) * data_length);
  memcpy(result->data, data, data_length);
  result->next = NULL;
  return result;
}

void append(strs *list, char *data)
{
  strs *tail = list;
  while (tail->next)
  {
    tail = tail->next;
  }
  tail->next = create_item(data, strlen(data));
}

void clean_list(strs *l)
{
  struct node *tmp;
  while (l)
  {
    tmp = l;
    l = l->next;
    if (tmp->data)
      free(tmp->data);
    free(tmp);
  }
}
//////////////////////////////////////////

int execute_command(msg *m, pb_crypto *pb_encryptor, char * out_buff)
{
  switch (m->command)
  {
  case PIN_BLOCK:
    printf("\033[1;30m[info]\033[0m: recieved PIN_BLOCK command\n");
    pin_block_args *pb_args = get_pin_block_args(m);
    pin_block *result = pb_crypto_make_encrypted_pin_block(pb_encryptor, pb_args);
    memcpy(out_buff, result->buff, BLOCK_BUFFER_SIZE);

    free(pb_args);
    free(result);
    return BLOCK_BUFFER_SIZE;

  case BATCH:
    printf("\033[1;30m[info]\033[0m: recieved BATCH command\n");
    break;

  case NEW_KEY:
    printf("\033[1;30m[info]\033[0m: recieved NEW_KEY command\n");
    break;

  case CHECK:
    printf("\033[1;30m[info]\033[0m: recieved CHECK command\n");
    check_args *args = get_check_args(m);
    *(out_buff) = pb_crypto_check_pin_block(pb_encryptor, args);
    free(args);
    return 1;

  default:
    break;
  }
  return 0;
}

pb_crypto *enc;

void process(const char *in_buffer, char *out, int buffer_length)
{
  if (!enc)
  {
    enc = pb_crypto_new();
    pb_crypto_set_key_from_file(enc, ".pinkey");
  }

  const char *in_buffer_ptr = in_buffer;
  int buf_offset = 0;
  while (buffer_length > buf_offset)
  {
    msg *m = msg_decode((uint8_t *)in_buffer_ptr);
    buf_offset += m->size + 2;
    in_buffer_ptr += buf_offset;
    int out_offset = execute_command(m, enc, out);
    out += out_offset;
    free(m);
  }

  // printf("buf_offset = %d", buf_offset);
  sprintf(out, "OK");
  fflush(stdout);
  printf("\n");
}

//////////////////////////////////////////////////////////////////////////////////////////

static void on_close(uv_handle_t *handle)
{
  free(handle);
}

static void after_write(uv_write_t *req, int status)
{
  write_req_t *wr = (write_req_t *)req;

  if (wr->buf.base != NULL)
    free(wr->buf.base);
  free(wr);
  uv_close((uv_handle_t *)req->handle, on_close);

  if (status == 0)
    return;

  fprintf(stderr, "uv_write error: %s\n", uv_strerror(status));

  if (status == UV_ECANCELED)
    return;

  assert(status == UV_EPIPE);
  uv_close((uv_handle_t *)req->handle, on_close);
}

static void after_shutdown(uv_shutdown_t *req, int status)
{
  /*assert(status == 0);*/
  pb_crypto_free(enc);

  if (status < 0)
    fprintf(stderr, "\033[1;31merr: %s\033[0m\n", uv_strerror(status));
  fprintf(stderr, "data received: %d\n", total_read);
  total_read = 0;
  uv_close((uv_handle_t *)req->handle, on_close);
  free(req);
}

static void after_read(uv_stream_t *handle,
                       ssize_t nread,
                       const uv_buf_t *buf)
{
  int r;
  write_req_t *wr;

  if (nread <= 0 && buf->base != NULL)
    free(buf->base);

  if (nread == 0)
    return;

  if (nread < 0)
  {
    fprintf(stderr, "err: %s\n", uv_strerror(nread));

    uv_shutdown_t *req = (uv_shutdown_t *)malloc(sizeof(*req));
    assert(req != NULL);

    r = uv_shutdown(req, handle, after_shutdown);
    assert(r == 0);

    return;
  }

  total_read += nread;

  wr = (write_req_t *)malloc(sizeof(*wr));
  assert(wr != NULL);

  char *response = malloc(sizeof(char) * nread * 2);
  memset(response, 0, nread * 2);

  process(buf->base, response, nread);

  wr->buf = uv_buf_init(response, nread * 2);

  r = uv_write(&wr->req, handle, &wr->buf, 1, after_write);
  assert(r == 0);

  free(buf->base);
}

static void alloc_cb(uv_handle_t *handle,
                     size_t suggested_size,
                     uv_buf_t *buf)
{
  buf->base = malloc(suggested_size);
  assert(buf->base != NULL);
  buf->len = suggested_size;
}

static void on_connection(uv_stream_t *server, int status)
{
  uv_tcp_t *stream;
  int r;

  assert(status == 0);

  stream = malloc(sizeof(uv_tcp_t));
  assert(stream != NULL);

  r = uv_tcp_init(uv_default_loop(), stream);
  assert(r == 0);

  stream->data = server;

  r = uv_accept(server, (uv_stream_t *)stream);
  assert(r == 0);

  r = uv_read_start((uv_stream_t *)stream, alloc_cb, after_read);
  assert(r == 0);
}

static int tcp_pin_bl_server()
{
  uv_tcp_t *tcp_server;
  struct sockaddr_in addr;
  int r;

  r = uv_ip4_addr("127.0.0.1", PORT, &addr);
  assert(r == 0);

  tcp_server = (uv_tcp_t *)malloc(sizeof(*tcp_server));
  assert(tcp_server != NULL);

  r = uv_tcp_init(loop, tcp_server);
  assert(r == 0);

  r = uv_tcp_bind(tcp_server, (const struct sockaddr *)&addr, 0);
  assert(r == 0);

  r = uv_listen((uv_stream_t *)tcp_server, SOMAXCONN, on_connection);
  assert(r == 0);

  return 0;
}

int main()
{
  int r;
  loop = uv_default_loop();

  r = tcp_pin_bl_server();
  assert(r == 0);

  r = uv_run(loop, UV_RUN_DEFAULT);
  assert(r == 0);

  return 0;
}