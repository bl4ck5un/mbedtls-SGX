#include "hkeygen.h"

#include <mbedtls/bignum.h>

#include <iostream>

#include "hybrid_cipher.h"

#define DEBUG_SECRET_KEY "cd244b3015703ddf545595da06ada5516628c5feadbf49dc66049c4b370cc5d8"

int main() {
  HybridEncryption enc_ctx;

  mbedtls_mpi secret_key;
  mbedtls_mpi_read_string(&secret_key, 16, DEBUG_SECRET_KEY);

  uint8_t secret_key_buffer[HybridEncryption::SECRET_KEY_SIZE];
  int ret = mbedtls_mpi_write_binary(&secret_key, secret_key_buffer,
                                     HybridEncryption::SECRET_KEY_SIZE);
  if (ret) {
    cerr << "invalid input" << endl;
    return -1;
  }

  ECPointBuffer pubkey;
  ret = HybridEncryption::secretToPubkey(&secret_key, pubkey);
  if (ret) {
    cerr << "invalid input" << endl;
    return -1;
  }

  char secret_key_b64[HybridEncryption::SECRET_KEY_SIZE * 2];
  char public_key_b64[HybridEncryption::PUBLIC_KEY_SIZE * 2];

  ext::b64_ntop(secret_key_buffer, HybridEncryption::SECRET_KEY_SIZE,
                secret_key_b64, sizeof secret_key_b64);

  ext::b64_ntop(pubkey, HybridEncryption::PUBLIC_KEY_SIZE,
                public_key_b64, sizeof public_key_b64);

//  hexdump("secret", secret_key_buffer, HybridEncryption::SECRET_KEY_SIZE);
//  hexdump("public", pubkey, HybridEncryption::PUBLIC_KEY_SIZE);
  printf("secret: %s\npublic: %s\n", secret_key_b64, public_key_b64);
}
