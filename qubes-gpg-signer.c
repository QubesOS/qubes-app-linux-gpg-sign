#define _FORTIFY_SOURCE 2
#include <unistd.h>
#include <err.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>

enum {
    ARGUMENT_LENGTH = 40,
    BAD_ARG_EXIT_STATUS = 16,
};

static char *get_prog_name(char *str)
{
    char *const res = strrchr(str, '/');
    return res ? res + 1 : str;
}

static const char *qubes_gpg_get_sign_request(void) {
    /*
     * Caller gets to choose between armored and binary signature.
     * The output of GnuPG is trusted, and it is trivially possible
     * to convert between them, so there are no security
     * implications to the choice.  Therefore, encoding the choice
     * in the service argument (which is used for access checks)
     * would be overly constraining.
     */
    for (;;) {
        char untrusted_buf[1];
        switch (read(0, untrusted_buf, sizeof untrusted_buf)) {
        case 0:
            errx(BAD_ARG_EXIT_STATUS, "No signature type selection byte (premature EOF)");
        case -1:
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            err(BAD_ARG_EXIT_STATUS, "Failed to read signature type byte");
        case 1:
            switch (untrusted_buf[0]) {
            case 'a':
                return "--armor";
            case 'b':
                return "--no-armor";
            default:
                errx(1, "Bad signature type byte %d", untrusted_buf[0]);
            }
            break;
        }
        abort();
    }
}

int main(int argc, char **argv) {
    if (argc != 2)
        errx(BAD_ARG_EXIT_STATUS, "Wrong number of arguments (expected 2, got %d)", argc);
    char *untrusted_arg = argv[1];
    const char *prog_name = get_prog_name(argv[0]);
    bool cleartext;

    if (!strcmp(prog_name, "qubes.GpgSign"))
        cleartext = false;
    else if (!strcmp(prog_name, "qubes.GpgClearSign"))
        cleartext = true;
    else
        errx(BAD_ARG_EXIT_STATUS, "Invoked with unknown basename %s, cannot determine operation to perform", prog_name);

    /* sanitize start */
    size_t const arg_len = strlen(untrusted_arg);
    if (arg_len != ARGUMENT_LENGTH)
        errx(BAD_ARG_EXIT_STATUS, "Invalid length of service argument (expected %d, got %zu)",
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
            errx(BAD_ARG_EXIT_STATUS, "Invalid byte %d at position %zu in argument %s",
                 untrusted_arg[i], i, untrusted_arg);
        }
    }
    /* sanitize end */

    /* Add a trailing ! to the key fingerprint.  This tells GnuPG to use the
     * exact key requested. */
    char uid_arg[ARGUMENT_LENGTH + 2];
    memcpy(uid_arg, untrusted_arg, arg_len);
    memcpy(uid_arg + arg_len, "!", 2);

    /* There is only one way to make a cleartext signature, but binary
     * signatures can be armored or unarmored. */
    const char *flag = cleartext ? NULL : qubes_gpg_get_sign_request();
    const char *args[] = {
        "gpg",
        "--batch",
        "--no-tty",
        "--sign",
        "--disable-dirmngr",
        "--quiet",
        "--utf8-strings",
        "--display-charset=UTF-8",
        "--status-fd=2",
        "--with-colons",
        /* Select detached or cleartext signatures */
        cleartext ? "--clearsign" : "--detach-sign",
        /* In case the user has --textmode or --no-textmode in gpg.conf */
        cleartext ? "--textmode" : "--no-textmode",
        "--local-user",
        uid_arg,
        flag,
        NULL,
    };
    execvp(args[0], (char *const *)args);
    err(127, "execvp(%s)", args[0]);
}
