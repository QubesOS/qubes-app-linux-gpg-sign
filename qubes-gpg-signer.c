#define _FORTIFY_SOURCE 2
#include <unistd.h>
#include <err.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

enum { ARGUMENT_LENGTH = 40 };

int main(int argc, char **argv) {
    if (argc != 2)
        errx(16, "Wrong number of arguments (expected 2, got %d)", argc);
    char *untrusted_arg = argv[1];
    size_t const arg_len = strlen(untrusted_arg);
    if (arg_len != ARGUMENT_LENGTH)
        errx(16, "Invalid length of service argument (expected %d, got %zu)",
             ARGUMENT_LENGTH, arg_len);
    for (size_t i = 0; i < arg_len; ++i) {
        switch (untrusted_arg[i]) {
        case '0' ... '9':
        case 'A' ... 'F':
            break;
        case 'a' ... 'f':
            untrusted_arg[i] &= 0xDF;
            break;
        default:
            /* Argument already sanitized by qrexec */
            errx(16, "Invalid byte %d at position %zu in argument %s",
                 untrusted_arg[i], i, untrusted_arg);
        }
    }
    char buf[1], uid_arg[ARGUMENT_LENGTH + 2];
    /* sanitization end */
    memcpy(uid_arg, untrusted_arg, arg_len);
    uid_arg[arg_len] = '!';
    uid_arg[arg_len + 1] = '\0';

    char *args[] = {
        "gpg",
        "--sign",
        "--batch",
        "--utf8-strings",
        "--display-charset=UTF-8",
        "--status-fd=2",
        "--exit-on-status-write-error",
        "--with-colons",
        "--detach-sign",
        "--local-user",
        uid_arg,
        NULL,
        NULL,
    };
    for (;;) {
        switch (read(0, buf, sizeof buf)) {
        case 0:
            errx(16, "No signature type selection byte (premature EOF)");
        case -1:
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            err(16, "Failed to read signature type byte");
        case 1:
            switch (buf[0]) {
            case 'a':
                args[sizeof(args)/sizeof(args[0]) - 2] = "--armor";
                break;
            case 'b':
                break;
            default:
                errx(1, "Bad signature type byte %d", buf[0]);
            }
            execvp("gpg", args);
            err(1, "execve(gpg)");
        }
        abort();
    }
}
