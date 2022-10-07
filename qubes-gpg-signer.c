/*
 * The Qubes OS Project, https://www.qubes-os.org
 *
 * Copyright (C) 2022  Demi Marie Obenour <demi@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

enum {
    ARGUMENT_LENGTH = 40,
    BAD_ARG_EXIT_STATUS = 16,
};

static void validate_argv0(const char *progname, bool *cleartext, const char **flag)
{
    if (!strcmp(progname, "qubes.GpgArmorSign"))
        (void)(*cleartext = false), *flag = "--armor";
    else if (!strcmp(progname, "qubes.GpgClearSign"))
        (void)(*cleartext = true), *flag = "--clearsign";
    else if (!strcmp(progname, "qubes.GpgBinarySign"))
        (void)(*cleartext = false), *flag = "--no-armor";
    else
        errx(BAD_ARG_EXIT_STATUS, "Must be invoked as qubes.GpgBinarySign, qubes.GpgArmorSign, or qubes.GpgClearSign, not %s.\n\
\n\
qubes.GpgBinarySign: create binary OpenPGP signatures\n\
qubes.GpgArmorSign: create ASCII-armored OpenPGP signatures\n\
qubes.GpgClearSign: create cleartext OpenPGP signatures", progname);
}

static char *get_prog_name(char *str)
{
    char *const res = strrchr(str, '/');
    return res ? res + 1 : str;
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

    validate_argv0(progname, &cleartext, &flag);

    /*
     * Sanitize the fingerprint and convert it to uppercase.  The argument is
     * already somewhat sanitized by qrexec.  It cannot be passed directly
     * to GnuPG, but it *is* safe to print.
     */
    /* sanitize start */
    size_t const arg_len = strlen(untrusted_arg);

    /* Check that the length is correct */
    if (arg_len != ARGUMENT_LENGTH)
        errx(BAD_ARG_EXIT_STATUS, "Invalid length of service argument \"%s\" (expected %d, got %zu)",
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
            errx(BAD_ARG_EXIT_STATUS, "Invalid character '%c' at position %zu in argument \"%s\"",
                 untrusted_uid[i], i + 1, untrusted_arg);
        }
    }
    const char *const uid = untrusted_uid;
    /* sanitize end */

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
        "--logger-file=/dev/null",
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
    err(126, "execvp(%s)", args[0]);
}
