#include <sgx_urts.h>
#include <stdio.h>
#include <iostream>

#include "Enclave_u.h"
#include "utils.h"

using namespace std;

sgx_enclave_id_t eid = 0;

/*
 * Example: hybridd encryption
 * encrypt a 32-byte key first, then encrypt an arbitrary long message.
 */

int main() {
  int ret;

  ret = initialize_enclave(&eid);
  if (ret != 0) {
    cerr << "failed to initialize the enclave" << endl;
    exit(-1);
  }
  printf("Enclave %lu created\n", eid);

  ssl_conn_init(eid);

exit:
  sgx_destroy_enclave(eid);
  printf("Info: all enclave closed successfully.\n");
  return 0;
}
