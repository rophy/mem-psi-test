/*
 * dentry-creator: rapidly creates hard links to inflate the kernel dentry cache.
 * Uses direct link() syscalls — no fork/exec overhead per file.
 *
 * Usage: dentry-creator <base_path> <count> [links_per_dir]
 *
 * Creates a source file at <base_path>/.src, then creates <count> hard links
 * spread across subdirectories (links_per_dir per directory, default 50000).
 *
 * On a typical system, this creates ~1M dentries/second vs ~1.5k/second in shell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

static int mkdirs(const char *path) {
    char tmp[4096];
    char *p;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <base_path> <count> [links_per_dir]\n", argv[0]);
        return 1;
    }

    const char *base = argv[1];
    long count = atol(argv[2]);
    long per_dir = argc > 3 ? atol(argv[3]) : 50000;

    if (count <= 0 || per_dir <= 0) {
        fprintf(stderr, "count and links_per_dir must be positive\n");
        return 1;
    }

    /* Create base directory */
    if (mkdirs(base) != 0) {
        perror("mkdirs base");
        return 1;
    }

    /* Create source file */
    char src[4096];
    snprintf(src, sizeof(src), "%s/.src", base);
    int fd = open(src, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        perror("create source file");
        return 1;
    }
    close(fd);

    printf("Creating %ld dentries at %s (%ld per dir)\n", count, base, per_dir);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    long created = 0;
    long dir_idx = 0;
    char dir_path[4096];
    char link_path[4096];

    while (created < count) {
        /* Create subdirectory */
        snprintf(dir_path, sizeof(dir_path), "%s/d%ld", base, dir_idx);
        if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
            perror("mkdir");
            break;
        }

        long i;
        long batch = per_dir;
        if (created + batch > count)
            batch = count - created;

        for (i = 0; i < batch; i++) {
            snprintf(link_path, sizeof(link_path), "%s/l%ld", dir_path, i);
            if (link(src, link_path) != 0) {
                if (errno == ENOSPC || errno == ENOMEM) {
                    fprintf(stderr, "Out of space/memory at %ld dentries\n", created);
                    goto done;
                }
                /* Ignore EEXIST, fail on others */
                if (errno != EEXIST) {
                    perror("link");
                    goto done;
                }
            }
            created++;
        }

        dir_idx++;

        /* Progress every 500k */
        if (created % 500000 == 0) {
            clock_gettime(CLOCK_MONOTONIC, &end);
            double elapsed = (end.tv_sec - start.tv_sec) +
                           (end.tv_nsec - start.tv_nsec) / 1e9;
            printf("  %ld / %ld (%.1fs, %.0f/s)\n",
                   created, count, elapsed, created / elapsed);
        }
    }

done:
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                   (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Created %ld dentries in %.2fs (%.0f/s)\n",
           created, elapsed, created / elapsed);

    return 0;
}
