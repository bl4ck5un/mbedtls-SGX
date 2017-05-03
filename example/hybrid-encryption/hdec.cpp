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
  printf("Usage: ./hdec secret(base64) user_input\n");
}

int main(int argc, const char *argv[]) {
  if (argc != 3) {
    _help();
    return -1;
  }
  ECPointBuffer server_pubkey;
  uint8_t secret_key_buffer[HybridEncryption::SECRET_KEY_SIZE];
  int ret = ext::b64_pton(argv[1], secret_key_buffer, HybridEncryption::SECRET_KEY_SIZE);
  if (ret != HybridEncryption::SECRET_KEY_SIZE) {
    cerr << "can't parse pubkey: " << argv[1] << endl;
    return -1;
  }

  mbedtls_mpi secret_key;
  mbedtls_mpi_read_binary(&secret_key, secret_key_buffer, HybridEncryption::SECRET_KEY_SIZE);

  try {
    HybridEncryption dec_ctx(&secret_key);
    HybridCiphertext cipher = dec_ctx.decode(argv[2]);

    vector<uint8_t> cleartext;
    dec_ctx.hybridDecrypt(cipher, cleartext);

    cout << string(cleartext.begin(), cleartext.end()) << endl;
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
