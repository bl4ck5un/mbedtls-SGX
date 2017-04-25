#ifndef MBEDTLS_SGX_ENC_H
#define MBEDTLS_SGX_ENC_H


#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>

#include <string.h>

#include <exception>
using namespace std;

#define DEBUG_BUFFER(title, buf, len) do { \
  mbedtls_debug_print_buf(&dummy_ssl_ctx, 0, __FILE__,__LINE__, title, buf, len); } \
 while (0);

#define CHECK_RET(ret) do { if (ret != 0) { throw runtime_error(err(ret)); }} while (0);
#define CHECK_RET_GO(ret,label) do { if (ret != 0) { goto label; }} while (0);


static void my_debug(void *ctx, int level, const char *file, int line,
                     const char *str) {
  (void) ctx;
  (void) level;

  mbedtls_printf("%s:%d: %s", file, line, str);
}

class HybridEncryption {
 public:
  typedef uint8_t AESKey[32];
  typedef uint8_t AESIv[32];
  typedef uint8_t GCMTag[16];
  typedef uint8_t ECPointBuffer[65];
  static const mbedtls_ecp_group_id EC_GROUP = MBEDTLS_ECP_DP_SECP256K1;
 private:
  // general setup
  const size_t PUBLIC_KEY_SIZE = 65;

  char err_msg[1024];
  int ret;
  uint8_t buf[100];

  // rng setup
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;

  // only used for debugging
  mbedtls_ssl_context dummy_ssl_ctx;
  mbedtls_ssl_config dummy_ssl_cfg;

  void dump_pubkey(const mbedtls_ecp_group* grp, const mbedtls_ecp_point* p, ECPointBuffer buf) {
    size_t olen;
    int ret = mbedtls_ecp_point_write_binary(grp, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, PUBLIC_KEY_SIZE);
    if (ret != 0 || olen != PUBLIC_KEY_SIZE) {
      throw runtime_error("mbedtls_ecp_point_write_binary failed");
    }
  }

  void load_pubkey(const mbedtls_ecp_group* grp, mbedtls_ecp_point*p, const ECPointBuffer buf) {
    int ret = mbedtls_ecp_point_read_binary(grp, p, buf, PUBLIC_KEY_SIZE);
    if (ret != 0) {
      throw runtime_error("mbedtls_ecp_point_read_binary failed");
    }
  }

  const char *err(int err) {
    mbedtls_strerror(err, err_msg, sizeof err_msg);
    return err_msg;
  }

 public:
  HybridEncryption() {
    ret = 0;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) "RANDOM_GEN", 10);

    if (ret != 0) {
      mbedtls_printf("failed in mbedtls_ctr_drbg_seed: %d\n", ret);
      mbedtls_strerror(ret, err_msg, sizeof err_msg);
      throw runtime_error(err_msg);
    }

    mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg,
                                               MBEDTLS_CTR_DRBG_PR_OFF);

    // debugging setup
    mbedtls_ssl_init(&dummy_ssl_ctx);
    mbedtls_ssl_config_init(&dummy_ssl_cfg);
    mbedtls_ssl_conf_dbg(&dummy_ssl_cfg, my_debug, NULL);
    if ((ret = mbedtls_ssl_setup(&dummy_ssl_ctx, &dummy_ssl_cfg)) != 0) {
      cout << ret << endl;
    };
    mbedtls_debug_set_threshold(100);
  }

  void fill_random(unsigned char* out, size_t len) {
    mbedtls_ctr_drbg_random(&ctr_drbg, out, len);
  }

  void hexdump(const char* title, uint8_t* buf, size_t len) {
    DEBUG_BUFFER(title, buf, len);
  }

  void initServer(mbedtls_mpi* seckey, ECPointBuffer pubkey) {
    mbedtls_ecdh_context ecdh_ctx_tc;
    mbedtls_ecdh_init(&ecdh_ctx_tc);

    // load the group
    ret = mbedtls_ecp_group_load(&ecdh_ctx_tc.grp, EC_GROUP);
    CHECK_RET(ret);

    cout << "Group loaded: nbits=" << ecdh_ctx_tc.grp.nbits << ", pbits=" << ecdh_ctx_tc.grp.pbits << endl;

    // generate an ephemeral key
    ret = mbedtls_ecdh_gen_public(&ecdh_ctx_tc.grp, &ecdh_ctx_tc.d, &ecdh_ctx_tc.Q,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    CHECK_RET(ret);

    // release the public key
    dump_pubkey(&ecdh_ctx_tc.grp, &ecdh_ctx_tc.Q, pubkey);

    ret = mbedtls_mpi_copy(seckey, &ecdh_ctx_tc.d);
    CHECK_RET(ret);
  }

  void hybridDecrypt(const ECPointBuffer user_pubkey, const mbedtls_mpi* secret_key) {
    mbedtls_ecdh_context ctx_tc;
    mbedtls_ecdh_init(&ctx_tc);

    // load the group
    ret = mbedtls_ecp_group_load(&ctx_tc.grp, EC_GROUP);
    if (ret != 0) {
      mbedtls_printf(" failed\n  ! mbedtls_ecp_group_load returned %d\n", ret);
      throw runtime_error(err(ret));
    }

    // load the sec key
    mbedtls_mpi_copy(&ctx_tc.d, secret_key);

    // load user's public key
    load_pubkey(&ctx_tc.grp, &ctx_tc.Qp, user_pubkey);

    // compute the shared secret
    ret = mbedtls_ecdh_compute_shared(&ctx_tc.grp, &ctx_tc.z,
                                      &ctx_tc.Qp, &ctx_tc.d,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
      mbedtls_printf(" failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret);
      throw runtime_error(err(ret));
    }

    mbedtls_debug_print_mpi(&dummy_ssl_ctx, 0, __FILE__, __LINE__, "derived secret", &ctx_tc.z);
  }

  void hybridEncrypt(const ECPointBuffer tc_pubkey, ECPointBuffer pubkey) {
    mbedtls_ecdh_context ctx_user;
    mbedtls_ecdh_init(&ctx_user);

    // load the group
    ret = mbedtls_ecp_group_load(&ctx_user.grp, EC_GROUP);
    CHECK_RET_GO(ret, cleanup);

    // generate an ephemeral key
    ret = mbedtls_ecdh_gen_public(&ctx_user.grp, &ctx_user.d, &ctx_user.Q,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    CHECK_RET_GO(ret, cleanup);

    dump_pubkey(&ctx_user.grp, &ctx_user.Q, pubkey);

    // populate with the tc public key
    // z == 1 means Z != infty
    ret = mbedtls_mpi_lset(&ctx_user.Qp.Z, 1);
    CHECK_RET_GO(ret, cleanup);

    load_pubkey(&ctx_user.grp, &ctx_user.Qp, tc_pubkey);

    // derive shared secret
    ret = mbedtls_ecdh_compute_shared(&ctx_user.grp, &ctx_user.z,
                                      &ctx_user.Qp, &ctx_user.d,
                                      NULL, NULL);
    CHECK_RET_GO(ret, cleanup);

    mbedtls_debug_print_mpi(&dummy_ssl_ctx, 0, __FILE__, __LINE__, "derived secret", &ctx_user.z);
  cleanup:
    mbedtls_ecdh_free(&ctx_user);
    if (ret) throw runtime_error(err(ret));
  }


  void aes_gcm_256_enc(const AESKey aesKey, const AESIv iv,
                       const uint8_t* data, size_t data_len,
                       GCMTag tag, uint8_t* cipher) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, aesKey, 8 * sizeof(AESKey));

    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, data_len,
                                    iv, sizeof(AESIv),
                                    NULL, 0,
                                    data,
                                    cipher, sizeof(GCMTag), tag);
    mbedtls_gcm_free(&ctx);
    CHECK_RET(ret);
  }

  void aes_gcm_256_dec(const AESKey aesKey, const AESIv iv,
                       const uint8_t* ciphertext, size_t ciphertext_len,
                       GCMTag tag, uint8_t* cleartext) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, aesKey, 8 * sizeof(AESKey));

    ret = mbedtls_gcm_auth_decrypt(&ctx, ciphertext_len,
                                   iv, sizeof(AESIv),
                                   NULL, 0,
                                   tag, sizeof(GCMTag),
                                   ciphertext, cleartext);
    mbedtls_gcm_free(&ctx);
    CHECK_RET(ret);
  }
};

#endif //MBEDTLS_SGX_ENC_H
