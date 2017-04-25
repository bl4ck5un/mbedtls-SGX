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
    HybridEncryption::ECPointBuffer server_pubkey;
    mbedtls_mpi server_seckey;
    mbedtls_mpi_init(&server_seckey);
    encrypt.initServer(&server_seckey, server_pubkey);

    HybridEncryption::ECPointBuffer user_pubkey;
    encrypt.hybridEncrypt(server_pubkey, user_pubkey);
    encrypt.hybridDecrypt(user_pubkey, &server_seckey);

    uint8_t text[100];
    memset(text, 0x92, sizeof text);
    uint8_t cipher[100];

    HybridEncryption::GCMTag tag;
    HybridEncryption::AESKey key;
    HybridEncryption::AESIv iv;

    encrypt.fill_random(key, sizeof key);
    encrypt.fill_random(iv, sizeof iv);

    encrypt.hexdump("key", key, sizeof key);
    encrypt.hexdump("iv", iv, sizeof iv);

    encrypt.aes_gcm_256_enc(key, iv, text, sizeof text, tag, cipher);

    encrypt.hexdump("tag", tag, sizeof tag);
    encrypt.hexdump("ciphertext", cipher, sizeof cipher);

    uint8_t temp[100];
    encrypt.aes_gcm_256_dec(key, iv, cipher, sizeof cipher, tag, temp);

    encrypt.hexdump("decrypted", temp, sizeof temp);
  }
  catch (const exception& e) {
    cerr << e.what() << endl;
  }

  catch (...) {
    cerr << "Unknown exception." << endl;
  }

}
