override CFLAGS += -Wall -Wextra -fsanitize=undefined -fsanitize-undefined-trap-on-error
.PHONY: all clean
#MAKEFLAGS := -r
%: %.o
	$(CC) -Wl,-z,relro,-z,now -fPIC -o $@ $^
%.o: %.c Makefile
	$(CC) $(CFLAGS) -O2 -ggdb -MD -MP -MF $@.dep -c -o $@ $< -Wp,-D_FORTIFY_SOURCE=2 -fPIC \
		-Werror=vla -Werror=array-bounds -Werror=format=2 -fstack-protector-all
all: qubes-gpg-signer
clean:
	rm -f ./*.o ./qubes-gpg-signer ./*.dep
-include ./*.o.dep
