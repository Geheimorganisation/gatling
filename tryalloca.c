#include <stdlib.h>
#ifdef A
#include <alloca.h>
#endif

main() {
  char* c=alloca(23);
}
