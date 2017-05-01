#include "enc.h"

#include <stdio.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>

#include <string>
#include <iostream>

using namespace std;

/*
 * Example: hybridd encryption
 * encrypt a 32-byte key first, then encrypt an arbitrary long message.
 */
int main(int argc, const char *argv[]) {
  HybridEncryption encrypt;
  try {
    ECPointBuffer server_pubkey;
    mbedtls_mpi server_seckey;
    mbedtls_mpi_init(&server_seckey);
    encrypt.initServer(&server_seckey, server_pubkey);

    cout << "simulating starts" << endl;

    while (true) {
      cout << "enter the text you want to encrypt and hit Enter: " << endl << "(empty line to exit): ";
      string user_secret;
      getline(cin, user_secret);
      if ((user_secret.empty()) || (cin.rdstate() & (cin.failbit | cin.badbit))) {
        cout << endl << "bye!" << endl;
        break;
      }

      cout << "----------------" << endl;
      hexDump("input", user_secret.data(), user_secret.size());
      cout << "----------------" << endl;

      string cipher_b64 = encrypt.hybridEncrypt(server_pubkey,
                                                reinterpret_cast<const uint8_t *>(user_secret.data()),
                                                user_secret.size());


      cout << "ciphertext (base64):\n" << cipher_b64;
      cout << "----------------" << endl;

      HybridCiphertext ciphertext = encrypt.decode(cipher_b64);

      vector<uint8_t> cleartext;
      encrypt.hybridDecrypt(ciphertext, &server_seckey, cleartext);

      hexDump("decrypted", cleartext.data(), cleartext.size());
      cout << "----------------" << endl;
    }
  }
  catch (const exception &e) {
    cerr << e.what() << endl;
  }

  catch (...) {
    cerr << "Unknown exception." << endl;
  }

}
