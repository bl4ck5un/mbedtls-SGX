# TLS for SGX: a port of mbedtls

mbedtls-SGX, based on [mbedtls](https://github.com/ARMmbed/mbedtls) (previously
PolarSSL), is an implementation of TLS protocol suite and a variety of
cryptographic primitives that can be within Intel SGX enclaves. In order to keep
the operating system out of the TCB, the core idea of this port is to have TLS
layers in the enclave and only call into the OS for transport services (TCP /
UDP). Treated as a big MITM, even a malicious OS can not tamper with the
security of TLS sessions originated from an SGX enclave.

# Source code structure

- `src`: source code of the trusted part of mbedtls-SGX
- `untrusted`: source code of the untrusted part of mbedtls-SGX (syscalls etc.)
- `include`: headers
- `example`: example programs (for both linux and Windows)
- `lib` [Deprecated]: compiled binaries (`.lib`) for **Windows** and the `.edl` file

# Usage

mbedtls-SGX is implemented as an enclave library.
To use it, you'll first need a working "SGX application" (i.e. an app and an enclave).
mbedtls-SGX is meant to be used in an enclave, not in untrusted applications.

## Linux

### with `cmake` (preferred)

```
git clone https://github.com/bl4ck5un/mbedtls-SGX && cd mbedtls-SGX
mkdir build && cd build
cmake ..
make -j
```

Use `build/libmbedtls_sgx_{t,u}.a` and `mbedtls_sgx.edl` in your project.  Link
`libmbedtls_sgx_u.a` to the untrusted part of your application and link
`libmbedtls_sgx_t.a` to your enclave.  See example for details.
Be sure to include `mbedtls_sgx.edl` in your enclave's EDL file. 
Also make sure your compiler can find the headers in `include`.

To build examples,

```
cmake .. -DCOMPILE_EXAMPLES
make -j
```

### with `make` 

```
git clone https://github.com/bl4ck5un/mbedtls-SGX && cd mbedtls-SGX
make
```

In `lib`, you'll get two static libraries and an EDL file.

```
$ ls lib
libmbedtls_sgx.a  libmbedtls_sgx_u.a mbedtls_sgx.edl  
```

Use `libmbedtls_sgx_{u,t}.a` and `mbedtls_sgx.edl` in your project
as shown in examples.

## Windows 

[Deprecated: I'm not maintaining the Windows version anymore]

# Examples

To be continued. See `example` for code.

# Missing features and workarounds

Due to SGX's contraints, some features have been turned off. 

- The lack of trusted wall-clock time. SGX provides trusted relative timer but not an absolute one. This affects checking expired certificates. A workaround is to maintain an internal clock and calibrate it frequently. 
- No access to file systems: mbedtls-SGX can not load CA files from file systems. To work this around, you need to hardcode root CAs as part of the enclave program. See `example/ExampleEnclave/RootCerts.{h,cpp}` for examples. 
- For a full configuration, see `src/mbedtls-2.2.1/include/mbedtls/config.h`.

# License

mbedtls-SGX is open source under Apache 2.0. See LICENSE for more details.
