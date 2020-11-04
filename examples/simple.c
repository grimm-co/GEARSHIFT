#include <stdlib.h>
#include <sys/types.h>

typedef struct {
  int first;
  int second;
} pair;

typedef struct {
  int myint;
  char mychar;
  size_t mysize;
  pair mypair;
  pair *pairptr;
} grabbag;

void fill_pair(pair *pairptr) {
  pairptr->first = rand();
  pairptr->second = 7;
}

int initgrabbag(grabbag *bag) {
  bag->pairptr = malloc(sizeof(bag->pairptr));
  fill_pair(&bag->mypair);
  fill_pair(bag->pairptr);
  bag->myint = 2;
  bag->mychar = 7;
  bag->mysize = 8;
  return bag->myint;
}

#ifdef INCLUDE_MAIN
int main() {
  grabbag bag;

  initgrabbag(&bag);
}
#endif
