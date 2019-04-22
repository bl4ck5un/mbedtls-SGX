# mbedtls-SGX: a TLS stack in SGX

mbedtls-SGX is a port of [mbedtls](https://github.com/ARMmbed/mbedtls) (previously PolarSSL) to Intel-SGX. mbedtls-SGX aims to preserve **all** of the [features of mbedtls](https://tls.mbed.org/core-features). With mbedtls-SGX, you can

- use a wide array of cryptographic primitives (hash, RSA, ECC, AES, etc) in SGX.
- build SGX-secured tls clients and servers -- even OS cannot access session secrets.
- enjoy the awesome [documentation](https://tls.mbed.org/kb) and clean [API](https://tls.mbed.org/api/) of mbedtls.

In addition, mbedtls-SGX comes with [examples](https://github.com/bl4ck5un/mbedtls-SGX/tree/master/example) to help you get started. Note that certain functionality is lost due to limitations of SGX. Read on for details.

# Usage and Examples

mbedtls-SGX is a static enclave library. General steps of using mbedtls-SGX in your project are:

- compile and install mbedtls-SGX (see below)
- include `trusted/mbedtls_sgx.edl` in your enclave's EDL file.
- make sure your compiler can find the headers in `include`.
- link `libmbedtls_sgx_u.a` to the untrusted part of your application
- link `libmbedtls_sgx_t.a` to your enclave. Note that mbedtls-SGX needs to be linked in the same group with other SGX standard libs. Your Makefile (or CMakeLists.txt) needs something like

```
-Wl,--start-group  -lmbedtls_sgx_t -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group
```

## Build

```
git clone https://github.com/bl4ck5un/mbedtls-SGX && cd mbedtls-SGX
mkdir build && cd build
cmake ..
make -j && make install
```

Include the resultant `mbedtls_SGX-2.16.1` as part of your project.

```
mbedtls_SGX-2.16.1
├── include
│   └── mbedtls
└── lib
    ├── libmbedtls_SGX_t.a
    ├── libmbedtls_SGX_u.a
    └── mbedtls_SGX.edl

```

## Examples

To compile examples, run cmake with `-DCOMPILE_EXAMPLES=YES`

```
cmake .. -DCOMPILE_EXAMPLES=YES
make -j
```

Three examples will be built

- `s_client`: a simple TLS client (by default it connects to `google.com:443`, dumps the HTML page and exits)
- `s_server`: a simple TLS server. You can play with it by `openssl s_client localhost:4433`.
- `m_server`: a multi-threaded TLS server, also listening at `localhost:4433` by default.

# Missing features and workarounds

Due to SGX's contraints, some features have been turned off.

- The lack of trusted wall-clock time. SGX provides trusted relative timer but not an absolute one. This affects checking expired certificates. A workaround is to maintain an internal clock and calibrate it frequently.
- No access to file systems: mbedtls-SGX can not load CA files from file systems. To work this around, you need to hardcode root CAs as part of the enclave program. See `example/enclave/ca_bundle.h` for an example.

# License

mbedtls-SGX is open source under Apache 2.0. See LICENSE for more details.
