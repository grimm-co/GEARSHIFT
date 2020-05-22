#include <stdio.h>
#include <stdlib.h>

typedef struct {
	char haha;
	int L;
	int L2;
	int L3;
} dec2;

typedef struct {
  char* buf;
  int length;
	dec2* lol;
	dec2* lol2;
} dec;

typedef struct {
  int return_code;
  int return_value;
  dec* buf;
} hack;

void atoi32(hack*);
int atoi_2(char*, int);

int main() {
  printf("Case 1 - Atoi\n");
  char buf[64];
  int len = read(0, buf, 64);
  if (buf[len-1] == '\n') {
    buf[len-1] = '\x00';
  } else {
    buf[len] = '\x00';
  }

  hack* test = (hack*) malloc(sizeof(hack));
  test->return_code = 0;
  test->return_value = 0;
  test->buf = (dec*) malloc(sizeof(dec));
  test->buf->buf = buf;
  test->buf->length = len - 1;

  atoi32(test);
  printf("Res: %d\n", test->return_value);
}

void atoi32(hack* test) {
  test->return_value = 0;
  char* ptr = test->buf->buf;
	test->buf->lol->L = 1;
	test->buf->lol->L2 = 2;
	test->buf->lol->L3 = 3;
	test->buf->lol->haha = 'A';
	test->buf->lol2->L = 4;
	test->buf->lol2->L2 = 5;
	test->buf->lol2->L3 = 6;
	test->buf->lol2->haha = 'B';
  for (int i = 0; i < test->buf->length; i++) {
    if (*ptr >= '0' && *ptr <= '9') {
      test->return_value = test->return_value * 10 + (*ptr - '0');
    } else {
      test->return_code = -1;
      return;
    }
    ptr++;
  }
  test->return_code = 0;
}

int atoi_2(char* buf, int length) {
  int ret = 0;
  char* ptr = buf;
  for (int i = 0; i < length; i++) {
    if (*ptr >= '0' && *ptr <= '9') {
      ret = ret * 10 + (*ptr - '0');
    } else {
      return -1;
    }
    ptr++;
  }
  return ret;
}
