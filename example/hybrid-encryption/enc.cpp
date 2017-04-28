#include <stdio.h>
#include <iostream>

using namespace std;

#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>

/*
 * Example: hybridd encryption
 * encrypt a 32-byte key first, then encrypt an arbitrary long message.
 */

#include "enc.h"

int main(int argc, const char *argv[]) {


  HybridEncryption encrypt;
  try {
    ECPointBuffer server_pubkey;
    mbedtls_mpi server_seckey;
    mbedtls_mpi_init(&server_seckey);
    encrypt.initServer(&server_seckey, server_pubkey);

    ECPointBuffer user_pubkey;

    uint8_t text[100];
    memset(text, 0x92, sizeof text);
    uint8_t cipher[100];

    GCMTag tag;
    AESKey key;
    AESIv iv;

    encrypt.fill_random(key, sizeof key);
    encrypt.fill_random(iv, sizeof iv);

    encrypt.hexdump("key", key, sizeof key);
    encrypt.hexdump("iv", iv, sizeof iv);

    HybridCiphertext ciphertext;
    encrypt.hybridEncrypt(server_pubkey, iv,
                          text, sizeof text,
                          ciphertext);
    encrypt.hexdump("tag", ciphertext.gcm_tag, sizeof ciphertext.gcm_tag);
    encrypt.hexdump("ciphertext", ciphertext.data.data(), ciphertext.data.size());

    vector<uint8_t> cleartext;
    encrypt.hybridDecrypt(ciphertext, &server_seckey, cleartext);

    encrypt.hexdump("decrypted", cleartext.data(), cleartext.size());
  }
  catch (const exception& e) {
    cerr << e.what() << endl;
  }

  catch (...) {
    cerr << "Unknown exception." << endl;
  }

}
