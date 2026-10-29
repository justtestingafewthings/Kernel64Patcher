#ifndef KERNEL64_ATOMIC_FILE_H
#define KERNEL64_ATOMIC_FILE_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct atomic_file {
    FILE *stream;
    char *temporary;
    const char *path;
};

/* Keep the temporary file beside its destination so rename stays atomic. */
static int atomic_file_open(struct atomic_file *file, const char *path) {
    static const char suffix[] = ".tmp.XXXXXX";
    memset(file, 0, sizeof(*file));
    size_t length = strlen(path);
    if (length > SIZE_MAX - sizeof(suffix)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    file->temporary = malloc(length + sizeof(suffix));
    if (!file->temporary) return -1;
    memcpy(file->temporary, path, length);
    memcpy(file->temporary + length, suffix, sizeof(suffix));
    file->path = path;

    int fd = mkstemp(file->temporary);
    if (fd >= 0) {
        file->stream = fdopen(fd, "wb");
        if (file->stream) return 0;
        int error = errno;
        close(fd);
        unlink(file->temporary);
        errno = error;
    }
    int error = errno;
    free(file->temporary);
    file->temporary = NULL;
    errno = error;
    return -1;
}

/* A failed write or close must leave the destination untouched. */
static int atomic_file_finish(struct atomic_file *file, int failed) {
    failed = failed || ferror(file->stream);
    int error = failed ? errno : 0;
    if (fclose(file->stream)) {
        failed = 1;
        error = errno;
    }
    file->stream = NULL;
    if (!failed && rename(file->temporary, file->path)) {
        failed = 1;
        error = errno;
    }
    if (failed) unlink(file->temporary);
    free(file->temporary);
    file->temporary = NULL;
    if (failed) errno = error ? error : EIO;
    return failed ? -1 : 0;
}

#endif
