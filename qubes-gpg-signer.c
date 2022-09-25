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

static bool validate_argv0(const char *progname, bool *cleartext, const char **flag)
{
    size_t len = strlen(progname);
    size_t const prefix_len = sizeof("qubes.Gpg") - 1;
    if (len < prefix_len + 4 ||
        memcmp(progname, "qubes.Gpg", prefix_len) ||
        memcmp(progname + len - 4, "Sign", 4))
        return false;
    len -= prefix_len + 4, progname += prefix_len;
    if (len == 0)
        return *cleartext = false, *flag = NULL, true;
    if (len == 5 && !memcmp(progname, "Clear", 5))
        return *cleartext = true, *flag = "--clearsign", true;
    if (len == 5 && !memcmp(progname, "Armor", 5))
        return *cleartext = false, *flag = "--armor", true;
    if (len == 6 && !memcmp(progname, "Binary", 6))
        return *cleartext = false, *flag = "--no-armor", true;
    return false;
}

int main(int argc, char **argv) {
    if (argc != 2)
        errx(BAD_ARG_EXIT_STATUS, "Wrong number of arguments (expected 2, got %d)", argc);

    /*
     * Argument already somewhat sanitized by qrexec: it cannot be passed
     * directly to GnuPG, but it *is* safe to print.
     */
    const char *const untrusted_arg = argv[1];
    const char *flag, *const progname = get_prog_name(argv[0]);
    bool cleartext;
    char untrusted_uid[ARGUMENT_LENGTH + 2] = { 0 };

    if (!validate_argv0(progname, &cleartext, &flag))
        errx(BAD_ARG_EXIT_STATUS, "Must be invoked as qubes.GpgSign, qubes.GpgArmorSign, qubes.GpgBinarySign, or qubes.GpgClearSign, not %s", progname);

    /*
     * Sanitize the fingerprint and convert it to uppercase.  The argument is
     * already somewhat sanitized by qrexec.  It cannot be passed directly
     * to GnuPG, but it *is* safe to print.
     */
    /* sanitize start */
    size_t const arg_len = strlen(untrusted_arg);

    /* Check that the length is correct */
    if (arg_len != ARGUMENT_LENGTH)
        errx(BAD_ARG_EXIT_STATUS, "Invalid length of service argument %s (expected %d, got %zu)",
             untrusted_arg, ARGUMENT_LENGTH, arg_len);

    /* Copy from the argument to the UID array */
    memcpy(untrusted_uid, untrusted_arg, arg_len);

    /*
     * Add a trailing ! to the key fingerprint.  This tells GnuPG to use the
     * exact key requested.  Also add the NUL terminator.
     */
    memcpy(untrusted_uid + arg_len, "!", 2);

    /* Sanitize and uppercase the user ID */
    for (size_t i = 0; i < arg_len; ++i) {
        switch (untrusted_uid[i]) {
        case '0' ... '9':
        case 'A' ... 'F':
            break;
        case 'a' ... 'f':
            untrusted_uid[i] -= 0x20;
            break;
        default:
            errx(BAD_ARG_EXIT_STATUS, "Invalid byte %d at position %zu in argument %s",
                 untrusted_uid[i], i, untrusted_arg);
        }
    }
    const char *const uid = untrusted_uid;
    /* sanitize end */

    /* There is only one way to make a cleartext signature, but binary
     * signatures can be armored or unarmored. */
    if (!flag && !cleartext)
        flag = qubes_gpg_get_sign_request();
    /* Ensure that GnuPG's locale is reasonable */
    if (putenv("LC_ALL=C.UTF-8"))
        err(127, "putenv(\"LC_ALL=C.UTF-8\")");
    const char *const args[] = {
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
        uid,
        flag,
        NULL,
    };
    execvp(args[0], (char *const *)args);
    err(127, "execvp(%s)", args[0]);
}
