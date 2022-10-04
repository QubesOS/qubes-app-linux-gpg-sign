ifeq ($(PACKAGE_SET),vm)
  ifneq ($(filter $(DISTRIBUTION), debian qubuntu),)
    DEBIAN_BUILD_DIRS := debian
  endif

  RPM_SPEC_FILES := rpm_spec/gpg-sign.spec
  ARCH_BUILD_DIRS := archlinux
endif

# vim: filetype=make
