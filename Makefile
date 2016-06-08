all:
	@make -C src
	@mkdir -p lib
	@echo "Installing.."
	@mv -f src/*.a lib
	@echo "Done."
