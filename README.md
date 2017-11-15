# mbedtls-SGX: a port of mbedtls to SGX

mbedtls-SGX is a port of [mbedtls](https://github.com/ARMmbed/mbedtls) (previously
PolarSSL) for Intel-SGX. mbedtls-SGX aims to preserve **all** of the functionality of mbedtls
permitted by SGX. With mbedtls-SGX, you can

- access a wide array of cryptographic primitives (hash, PRNG, RSA, ECC, AES, etc) in SGX.
- build SGX-secured tls clients and servers -- even OS cannot access session secrets.
- enjoy the awesome [documentation](https://tls.mbed.org/kb) and clean [API](https://tls.mbed.org/api/) of mbedtls.
- use cmake to build on whatever toolchain / platform you like.

In addition, mbedtls-SGX comes with examples to help you get started.
Note that certain functionality is lost due to limitations of SGX. Read on for details.

# Update

- [2017.11.14] Release a port of mbedtls-2.6.0. See `trusted/CHANGELOG` for modifications.
- [2017.11.14] The support for Windows is droped. If you want to help maintain
  a version for Windows, please contact me.


# Examples
See `example` for code.

# Usage

mbedtls-SGX is an enclave library. To use it,
you'll first need a working "SGX application" (i.e. an app and an enclave).
mbedtls-SGX is meant to be used in an enclave, not in untrusted applications.

## Linux

### with `cmake` (preferred)

```
git clone https://github.com/bl4ck5un/mbedtls-SGX && cd mbedtls-SGX
mkdir build && cd build
cmake ..
make -j
```

General steps to use mbedtls-SGX with your project:

- link `libmbedtls_sgx_u.a` to the untrusted part of your application
- link `libmbedtls_sgx_t.a` to your enclave.
- include `trusted/mbedtls_sgx.edl` in your enclave's EDL file.
- make sure your compiler can find the headers in `include`.

See example for details. To compile examples, run cmake with `-DCOMPILE_EXAMPLES=YES`

```
cmake .. -DCOMPILE_EXAMPLES=YES
make -j
```

Three examples will be built

- `s_client`: a simple TLS client (by default it connects to `google.com:443`, dumps the HTML page and exits)
- `s_server`: a simple TLS server. You can play with it by `openssl s_client localhost:4433`.
- `m_server`: a multi-threaded TLS server, also listening at `localhost:4433` by default.

### with `make`

I tried to maintain Makefiles the best I can. You can use make to build mbedtls-SGX,
but currently the examples can only be built by cmake.

```
git clone https://github.com/bl4ck5un/mbedtls-SGX && cd mbedtls-SGX
make
```

In `lib`, you'll get two static libraries.
se `libmbedtls_sgx_{u,t}.a` and `mbedtls_sgx.edl` in your project
as shown in examples.

## Windows

[Deprecated: I'm not maintaining the Windows version anymore]


# Missing features and workarounds

Due to SGX's contraints, some features have been turned off.

- The lack of trusted wall-clock time. SGX provides trusted relative timer but not an absolute one. This affects checking expired certificates. A workaround is to maintain an internal clock and calibrate it frequently.
- No access to file systems: mbedtls-SGX can not load CA files from file systems. To work this around, you need to hardcode root CAs as part of the enclave program. See `example/enclave/ca_bundle.h` for an example.

# License

mbedtls-SGX is open source under Apache 2.0. See LICENSE for more details.
