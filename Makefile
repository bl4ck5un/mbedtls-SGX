MBEDTLS_VERSION=2.6.0

all:
	@make -C trusted
	@make -C ocall
	@mkdir -p lib
	@echo "Installing.."
	@mv -f trusted/*.a ocall/*.a lib
	@echo "Done."
clean:
	@make -C trusted/mbedtls-$(MBEDTLS_VERSION)/ clean
	@make -C trusted clean
