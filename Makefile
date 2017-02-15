all:
	@make -C src
	@mkdir -p lib
	@echo "Installing.."
	@mv -f src/*.a lib
	@echo "Done."
clean:
	@make -C src/mbedtls-2.2.1/ clean
	@make -C src clean
