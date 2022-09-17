BUILDDIR ?= build
.PHONY: all clean install
$(BUILDDIR)/%: $(BUILDDIR)/%.o
	$(CC) -Wl,-z,relro,-z,now -fPIC -o $@ $^
$(BUILDDIR)/%.o: %.c Makefile $(BUILDDIR)/
	$(CC) $(CFLAGS) -O2 -ggdb -MD -MP -MF $@.dep -c -o $@ $< -Wp,-D_FORTIFY_SOURCE=2 -fPIC \
		-Werror=vla -Werror=array-bounds -Werror=format=2 -fstack-protector-all \
		-Wall -Wextra -fsanitize=undefined -fsanitize-undefined-trap-on-error
all: $(BUILDDIR)/qubes-gpg-signer
	for i in '' Clear Armor Binary; do ln -f -- $(BUILDDIR)/qubes-gpg-signer $(BUILDDIR)/qubes.Gpg$${i}Sign; done
$(BUILDDIR)/:
	mkdir -p -m 0700 -- $(BUILDDIR)
clean:
	rm -f -- $(BUILDDIR)/*.o $(BUILDDIR)/qubes-gpg-signer $(BUILDDIR)/*.dep
install:
	install -D -- $(BUILDDIR)/qubes.GpgSign ${DESTDIR}/etc/qubes-rpc/qubes.GpgSign
	ln -f -- ${DESTDIR}/etc/qubes-rpc/qubes.GpgSign ${DESTDIR}/etc/qubes-rpc/qubes.GpgClearSign
-include $(BUILDDIR)/*.o.dep
