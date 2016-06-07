all:
	@make -C src
	@mkdir -p lib
	@mv -f src/*.a lib
	@echo "Done."
