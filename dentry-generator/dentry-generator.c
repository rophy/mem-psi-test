/*
 * dentry-generator: continuously generates dentries at a configurable rate.
 *
 * Modes:
 *   positive  - creates hard links (persistent files, shared inode, ~192 bytes each)
 *   negative  - create + unlink per file (unreferenced dentries, mimics MariaDB temp tables)
 *
 * The generator runs indefinitely, creating dentries at the target rate.
 * It prints periodic stats (count, actual rate, slab usage if readable).
 *
 * Usage: dentry-generator <base_path> [options]
 *   --rate N       target dentries per second (default: 1000)
 *   --mode M       "positive" or "negative" (default: negative)
 *   --per-dir N    entries per subdirectory (default: 50000)
 *   --max N        stop after N total dentries (default: unlimited)
 *
 * Runs until killed or --max is reached. Designed to run inside a container.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>

static volatile int running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

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

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Sleep for fractional seconds using nanosleep */
static void sleep_frac(double seconds) {
    if (seconds <= 0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)seconds;
    ts.tv_nsec = (long)((seconds - ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
}

/* Create one positive dentry (hard link to src) */
static int create_positive(const char *path, const char *src) {
    if (link(src, path) != 0) {
        if (errno == ENOSPC || errno == ENOMEM) return -1;
        return 0; /* EEXIST or other transient */
    }
    return 1;
}

/* Create one negative dentry (create file, then unlink) */
static int create_negative(const char *path) {
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) {
        if (errno == ENOSPC || errno == ENOMEM) return -1;
        return 0;
    }
    close(fd);
    unlink(path);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <base_path> [--rate N] [--mode positive|negative] "
            "[--per-dir N] [--max N]\n", argv[0]);
        return 1;
    }

    const char *base = argv[1];
    long rate = 1000;
    int mode_negative = 1;
    long per_dir = 50000;
    long max_count = 0; /* 0 = unlimited */

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc)
            rate = atol(argv[++i]);
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode_negative = (strcmp(argv[++i], "positive") != 0);
        } else if (strcmp(argv[i], "--per-dir") == 0 && i + 1 < argc)
            per_dir = atol(argv[++i]);
        else if (strcmp(argv[i], "--max") == 0 && i + 1 < argc)
            max_count = atol(argv[++i]);
    }

    if (rate <= 0 || per_dir <= 0) {
        fprintf(stderr, "rate and per-dir must be positive\n");
        return 1;
    }

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    if (mkdirs(base) != 0) {
        perror("mkdirs base");
        return 1;
    }

    /* For positive mode, create a source file for hard links */
    char src[4096];
    if (!mode_negative) {
        snprintf(src, sizeof(src), "%s/.src", base);
        int fd = open(src, O_CREAT | O_WRONLY, 0644);
        if (fd < 0) { perror("create source"); return 1; }
        close(fd);
    }

    printf("dentry-generator: rate=%ld/s, mode=%s, base=%s",
           rate, mode_negative ? "negative" : "positive", base);
    if (max_count > 0)
        printf(", max=%ld", max_count);
    printf("\n");
    fflush(stdout);

    /*
     * Rate control strategy:
     * Process time in 100ms windows. Each window targets (rate / 10) dentries.
     * After creating the batch, sleep for the remainder of the window.
     * This gives smooth output without busy-waiting.
     */
    long batch_size = rate / 10;
    if (batch_size < 1) batch_size = 1;
    double window = (double)batch_size / rate; /* seconds per batch */

    long total = 0;
    long dir_idx = 0;
    long file_idx = 0;
    char dir_path[4096], path[4096];
    double start_time = now_sec();
    double last_report = start_time;

    /* Pre-create first directory */
    snprintf(dir_path, sizeof(dir_path), "%s/d%ld", base, dir_idx);
    mkdirs(dir_path);

    while (running) {
        double batch_start = now_sec();
        long batch_done = 0;

        while (batch_done < batch_size && running) {
            /* Rotate directory when full */
            if (file_idx >= per_dir) {
                dir_idx++;
                file_idx = 0;
                snprintf(dir_path, sizeof(dir_path), "%s/d%ld", base, dir_idx);
                if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
                    perror("mkdir");
                    running = 0;
                    break;
                }
            }

            snprintf(path, sizeof(path), "%s/f%ld", dir_path, file_idx);
            file_idx++;

            int rc;
            if (mode_negative)
                rc = create_negative(path);
            else
                rc = create_positive(path, src);

            if (rc < 0) {
                fprintf(stderr, "Out of space/memory at %ld total\n", total);
                running = 0;
                break;
            }
            if (rc > 0) {
                total++;
                batch_done++;
            }

            if (max_count > 0 && total >= max_count) {
                running = 0;
                break;
            }
        }

        /* Report every 5 seconds */
        double now = now_sec();
        if (now - last_report >= 5.0) {
            double elapsed = now - start_time;
            double actual_rate = total / elapsed;
            printf("[%6.0fs] total=%ld  rate=%.0f/s (target=%ld/s)\n",
                   elapsed, total, actual_rate, rate);
            fflush(stdout);
            last_report = now;
        }

        /* Sleep for remainder of window to maintain target rate */
        double batch_elapsed = now_sec() - batch_start;
        double sleep_time = window - batch_elapsed;
        sleep_frac(sleep_time);
    }

    double elapsed = now_sec() - start_time;
    printf("\nStopped: %ld dentries in %.1fs (avg %.0f/s)\n",
           total, elapsed, total / elapsed);

    return 0;
}
