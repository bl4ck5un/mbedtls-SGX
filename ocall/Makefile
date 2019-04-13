UNTRUSTED_SRC_FILES := ../ocall/net_ocalls.c ../ocall/std_ocalls.c
UNTRUSTED_OBJECTS := $(UNTRUSTED_SRC_FILES:.c=.u.o)

libmbedtls_sgx_u.a:	$(UNTRUSTED_OBJECTS)
	@ar rcs $@ $^
	@echo "LD => $@"

%.u.o: %.c
	@$(CC) -I../trusted/mbedtls-2.17.0/include -c -o $@ $<
	@echo "CC <= $<"

.PHONY: clean

clean:
	@rm -f $(UNTRUSTED_OBJECTS) $(PROJECT_NAME)_u.*

