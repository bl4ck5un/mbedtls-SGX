#include <stdio.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>

#include <string>
#include <iostream>

#include "hybrid_cipher.h"
#include "base64.hxx"

using namespace std;

void _help(void) {
  printf("Usage: ./henc pubkey user_input\n");
}

int main(int argc, const char *argv[]) {
  if (argc != 3) {
    _help();
    return -1;
  }
  ECPointBuffer server_pubkey;
  int ret = ext::b64_pton(argv[1], server_pubkey, sizeof(ECPointBuffer));
  if (ret != sizeof(ECPointBuffer)) {
    cerr << "can't parse pubkey: " << argv[1] << endl;
    return -1;
  }

  string user_secret(argv[2]);

  HybridEncryption encrypt;

  try {
    string cipher_b64 = encrypt.hybridEncrypt(server_pubkey,
                                              reinterpret_cast<const uint8_t *>(user_secret.data()),
                                              user_secret.size());
    cout << cipher_b64 << endl;
    return 0;
  }
  catch (const exception &e) {
    cerr << e.what() << endl;
    return -1;
  }

  catch (...) {
    cerr << "Unknown exception." << endl;
    return -1;
  }

}
