# TLS for SGX: a port of mbedtls

mbedtls-SGX, based on [mbedtls](https://github.com/ARMmbed/mbedtls) (previously PolarSSL), is an implementation of TLS protocol suite and a variety of cryptographic primitives that can be in Intel SGX enclaves. In order to exclude OSes from the TCB, the core idea of this port is to have TLS layers in the enclave and only call into OSes for transport services (TCP / UDP). Treated as a big MITM, even malicious OSes can not tamper with the security of TLS.

# Source code structure

- `example`: an example application (Windows only for the moment) and enclave showing how to configure and link with mbedtls-SGX.
- `lib`: release directory of mbedtls-SGX, including compiled binaries (`.lib`) for Windows and the `.edl` file.
- `include`: headers.
- `src`: source code of mbedtls-SGX. On Windows, you don't have to compile `src` to use the library.

# Usage

mbedtls-SGX is implemented as an enclave library (see [SDK documentation](https://software.intel.com/sites/products/sgx-sdk-users-guide-windows/Default.htm) for terminologies). To use it, you'll first need a working SGX application (i.e. an application and an enclave). **mbedtls-SGX is only meant to be used in an enclave, not in a untrusted application**.

## Linux

Simply `make` in the root directory.

```
make
```

In `lib`, you'll get two static libraries and an EDL file.

```
$ ls lib
libmbedtls_sgx.a  libmbedtls_sgx_u.a mbedtls_sgx.edl  
```

Link `libmbedtls_sgx_u.a` to the untrusted part of your application and link
`libmbedtls_sgx.a` to your enclave. 

Be sure to include `mbedtls_sgx.edl` in your enclave's EDL file. 
Also be sure your compiler can find the headres in `include`.

## Windows 


Suppose you've got an SGX application ready, take following steps to use mbedtls-SGX:

Configuration for the enclave project:

1. Add `lib/include` to the `Include Directories` ![include](docs/include.png)
2. Add `lib/mbedtls_tlib.lib` as an additional dependencies ![link-input](docs/link-input.png)
3. Add `lib` to the `Library Directories` ![lib](docs/lib-directory.png)
4. Import `lib/mbedtls_tlib.edl` in your edl file

Configuration for the application project:

1. Add the untrusted C file (`lib/mbedtls_u.c`) to application. ![lib](docs/add-untrust.png)

See `example` for a working example. 

# Missing features and workarounds

Due to SGX's contraints, some features have been turned off. 

- The lack of trusted wall-clock time. SGX provides trusted relative timer but not an absolute one. This affects checking expired certificates. A workaround is to maintain an internal clock and calibrate it frequently. 
- No access to file systems: mbedtls-SGX can not load CA files from file systems. To work this around, you need to hardcode root CAs as part of the enclave program. See `example/ExampleEnclave/RootCerts.{h,cpp}` for examples. 
- For a full configuration, see `src/mbedtls-2.2.1/include/mbedtls/config.h`.

# FAQ

## Error: Can not load enclave file with `CreateFile`

In `Debugging` configuration, change `Working Directory` from `$(TargetDir)$` (or alike) to `$(OutDir)`.

![can-not-load](docs/can not load.png)

# License

mbedtls-SGX is open source under Apache 2.0. See LICENSE for more details.
