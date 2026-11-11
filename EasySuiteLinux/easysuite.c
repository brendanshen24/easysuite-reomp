/* EasySuite for Linux. Logs in as a Mac-class peer (OS 0x14, big-endian,
   POSIX paths) so Mac, Windows, and the original EasySuite all understand it.
   Build on Linux: make    (needs libgtk-3-dev and libfuse3-dev)
   Protocol self-test, including on a Mac: make selftest */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 31
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <gtk/gtk.h>
#include <mntent.h>
#include <pthread.h>
#include <scsi/sg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include "proto.h"

typedef struct {
    pthread_mutex_t mu, op;
    pthread_cond_t cv;
    int sg;
    char skipdev[64];
    Es *es;
    volatile int stop;
    int busy;
    uint16_t cur[1024];
    int ncur;
    GtkWidget *window, *list, *status, *pathlab;
    GtkListStore *store;
    struct fuse *fuse;
} Plat;

static Plat g;

static void plock(void *u) { pthread_mutex_lock(&((Plat *)u)->mu); }
static void punlock(void *u) { pthread_mutex_unlock(&((Plat *)u)->mu); }
static void pwait(void *u, int ms) {
    Plat *p = u; struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000; ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    pthread_cond_timedwait(&p->cv, &p->mu, &ts);
}
static void pwake(void *u) { pthread_cond_broadcast(&((Plat *)u)->cv); }
static void poplock(void *u) { pthread_mutex_lock(&((Plat *)u)->op); }
static void popunlock(void *u) { pthread_mutex_unlock(&((Plat *)u)->op); }
static uint32_t pnow(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}
static gboolean status_idle(gpointer p) {
    if (g.status) gtk_label_set_text(GTK_LABEL(g.status), p);
    free(p); return G_SOURCE_REMOVE;
}
static void plog(void *u, const char *msg) {
    (void)u; FILE *f = fopen("/tmp/easysuite.log", "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
    if (g.status) g_idle_add(status_idle, strdup(msg));
}

static int sense_oti(const unsigned char *s) {
    unsigned key = s[2] & 0x0f, asc = s[12], ascq = s[13];
    if (key == 9 && asc >= 0x80 && asc <= 0x89 && ascq == 0) return (int)asc;
    unsigned k = (key << 16) | (asc << 8) | ascq;
    switch (k) {
    case 0x00000: return 4; case 0x23A00: case 0x63F0E: return 5;
    case 0x52000: case 0x72700: return 6; case 0x52400: return 7; case 0x62800: return 8;
    default: return 0xffff;
    }
}
static int sg_raw(int fd, const unsigned char *cdb, void *buf, unsigned len, int dir) {
    unsigned char sense[32]; sg_io_hdr_t io; memset(&io, 0, sizeof io);
    io.interface_id = 'S'; io.cmd_len = 16; io.mx_sb_len = sizeof sense;
    io.dxfer_direction = dir == 1 ? SG_DXFER_FROM_DEV : (len ? SG_DXFER_TO_DEV : SG_DXFER_NONE);
    io.dxfer_len = len; io.dxferp = buf; io.cmdp = (unsigned char *)cdb; io.sbp = sense;
    io.timeout = dir == 1 ? 2000 : 1000;
    if (ioctl(fd, SG_IO, &io) < 0) return -1;
    if ((io.status & 0x3e) == 0 && io.host_status == 0 && (io.driver_status & 0x08) == 0) return 0;
    return sense_oti(sense);
}
static int pscsi(void *u, uint8_t op, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, void *buf, uint32_t len, int dir) {
    unsigned char cdb[16] = {op, b1, b2, b3, b4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'O', 'T'};
    return sg_raw(((Plat *)u)->sg, cdb, buf, len, dir);
}
static int product_ok(const char *p) {
    char b[80]; size_t n = 0;
    for (; p[n] && n + 1 < sizeof b; n++) b[n] = (char)(p[n] >= 'A' && p[n] <= 'Z' ? p[n] - 'A' + 'a' : p[n]);
    b[n] = 0;
    const char *names[] = {"easysuite", "easycopy-net", "easycopy", "easysync", "thunder bird", "crossbox",
                           "simpletransfer", "superlink", "sugoi cable", "ez share", NULL};
    for (int i = 0; names[i]; i++) if (strstr(b, names[i])) return 1;
    return 0;
}
static void unescape_mnt(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (r[0] == '\\' && r[1] == '0' && r[2] == '4' && r[3] == '0') { *w++ = ' '; r += 4; }
        else *w++ = *r++;
    }
    *w = 0;
}
static void unmount_sg(int n) {
    char dir[256]; snprintf(dir, sizeof dir, "/sys/class/scsi_generic/sg%d/device/block", n);
    DIR *d = opendir(dir); if (!d) return;
    struct dirent *de; char dev[64] = {0};
    while ((de = readdir(d))) if (de->d_name[0] != '.') { snprintf(dev, sizeof dev, "%s", de->d_name); break; }
    closedir(d); if (!dev[0]) return;
    snprintf(g.skipdev, sizeof g.skipdev, "%s", dev);
    FILE *f = fopen("/proc/mounts", "r"); char line[768];
    while (f && fgets(line, sizeof line, f)) {
        char src[256], mnt[512];
        if (sscanf(line, "%255s %511s", src, mnt) != 2) continue;
        unescape_mnt(mnt);
        if (strstr(src, dev)) umount2(mnt, MNT_DETACH);
    }
    if (f) fclose(f);
}
static int open_cable(void) {
    for (int i = 0; i < 32; i++) {
        char path[64]; snprintf(path, sizeof path, "/dev/sg%d", i);
        int fd = open(path, O_RDWR | O_EXCL | O_NONBLOCK);
        if (fd < 0) fd = open(path, O_RDWR | O_NONBLOCK);
        if (fd < 0) continue;
        unsigned char inq[96] = {0}, cdb[16] = {0x12, 0, 0, 0, 96, 0};
        sg_io_hdr_t io; memset(&io, 0, sizeof io);
        io.interface_id = 'S'; io.cmd_len = 6; io.mx_sb_len = 32; io.dxfer_direction = SG_DXFER_FROM_DEV;
        io.dxfer_len = sizeof inq; io.dxferp = inq; io.cmdp = cdb; io.timeout = 1000;
        unsigned char sense[32]; io.sbp = sense;
        if (ioctl(fd, SG_IO, &io) < 0) { close(fd); continue; }
        char prod[20]; memcpy(prod, inq + 16, 16); prod[16] = 0;
        for (int k = 15; k >= 0 && (prod[k] == ' ' || !prod[k]); k--) prod[k] = 0;
        if (!product_ok(prod)) { close(fd); continue; }
        int flags = fcntl(fd, F_GETFL, 0); if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        unmount_sg(i); g.sg = fd; plog(&g, "Cable opened."); return 1;
    }
    return 0;
}
static void close_cable(void) { if (g.sg >= 0) close(g.sg); g.sg = -1; }

static int fs_ok(const char *t) {
    const char *ok[] = {"ext2", "ext3", "ext4", "btrfs", "xfs", "zfs", "f2fs", "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "bcachefs", "apfs", "hfs", "hfsplus", NULL};
    for (int i = 0; ok[i]; i++) if (!strcmp(t, ok[i])) return 1;
    return 0;
}
static void add_vol(EsVol *v, int *n, int cap, uint8_t type, const char *name, const char *path) {
    if (*n >= cap) return;
    for (int i = 0; i < *n; i++) {
        char have[1024]; es_utf8_from_u16(v[i].path, v[i].npath, have, sizeof have);
        if (!strcmp(have, path)) return;
    }
    memset(&v[*n], 0, sizeof v[*n]);
    v[*n].letter = 'A'; v[*n].type = type;
    v[*n].nname = es_u16_from_utf8(name, v[*n].name, 260);
    v[*n].npath = es_u16_from_utf8(path, v[*n].path, 1024);
    (*n)++;
}
static int lin_volumes(void *user, EsVol **out, int *count) {
    (void)user; EsVol *v = (EsVol *)calloc(64, sizeof *v); int n = 0;
    FILE *f = setmntent("/proc/mounts", "r"); struct mntent *e;
    while (f && (e = getmntent(f)) && n < 48) {
        if (!fs_ok(e->mnt_type)) continue;
        if (g.skipdev[0] && strstr(e->mnt_fsname, g.skipdev)) continue;
        const char *base = strrchr(e->mnt_dir, '/'); base = base && base[1] ? base + 1 : "Computer";
        if (!strcmp(e->mnt_dir, "/")) base = "Computer";
        uint8_t type = 0x12;
        if (!strncmp(e->mnt_dir, "/media", 6) || !strncmp(e->mnt_dir, "/run/media", 10) || !strcmp(e->mnt_type, "vfat") || !strcmp(e->mnt_type, "exfat")) type = 0x11;
        add_vol(v, &n, 64, type, base, e->mnt_dir);
    }
    if (f) endmntent(f);
    const char *home = getenv("HOME");
    if (home) {
        const char *subs[] = {"", "/Desktop", "/Documents", "/Downloads", "/Pictures", "/Music", "/Videos", NULL};
        const char *names[] = {"Home", "Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"};
        for (int i = 0; subs[i]; i++) {
            char path[1024]; snprintf(path, sizeof path, "%s%s", home, subs[i]);
            struct stat st; if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) add_vol(v, &n, 64, 0x16, names[i], path);
        }
    }
    *out = v; *count = n; return 0;
}
static char *u_path(const uint16_t *p, int n) { char *s = (char *)malloc((size_t)n * 3 + 4); es_utf8_from_u16(p, n, s, n * 3 + 4); return s; }
static void dent_from_stat(EsDent *d, const char *name, const struct stat *st) {
    memset(d, 0, sizeof *d);
    d->isdir = S_ISDIR(st->st_mode); d->size = S_ISDIR(st->st_mode) ? 0 : (uint64_t)st->st_size;
    d->mtime = (uint64_t)st->st_mtime; d->ctime = (uint64_t)st->st_ctime;
    d->nname = es_u16_from_utf8(name, d->name, 256);
}
static int lin_list(void *user, const uint16_t *path, int n, EsDent **out, int *count) {
    (void)user; char *dir = u_path(path, n); DIR *dp = opendir(dir); free(dir);
    EsDent *d = NULL; int c = 0, cap = 0;
    if (!dp) { *out = NULL; *count = 0; return -1; }
    struct dirent *de;
    while ((de = readdir(dp))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        if (c == cap) { cap = cap ? cap * 2 : 32; d = (EsDent *)realloc(d, (size_t)cap * sizeof *d); }
        char *base = u_path(path, n); char full[4096];
        snprintf(full, sizeof full, "%s%s%s", base, (n == 1 && path[0] == '/') ? "" : "/", de->d_name);
        free(base);
        struct stat st; if (lstat(full, &st) != 0) continue;
        dent_from_stat(&d[c], de->d_name, &st); c++;
    }
    closedir(dp); *out = d; *count = c; return 0;
}
static int lin_stat(void *user, const uint16_t *path, int n, int *isdir, uint64_t *size, uint64_t *mtime) {
    (void)user; char *s = u_path(path, n); struct stat st; int rc = lstat(s, &st); free(s);
    if (rc) return -1; *isdir = S_ISDIR(st.st_mode); *size = (uint64_t)st.st_size; *mtime = (uint64_t)st.st_mtime; return 0;
}
static int lin_mkdir(void *user, const uint16_t *path, int n) { (void)user; char *s = u_path(path, n); int rc = mkdir(s, 0755); free(s); return rc; }
static int lin_rename(void *user, const uint16_t *a, int na, const uint16_t *b, int nb) {
    (void)user; char *x = u_path(a, na), *y = u_path(b, nb); int rc = rename(x, y); free(x); free(y); return rc;
}
static int rm_rf(const char *path) {
    struct stat st; if (lstat(path, &st)) return -1;
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
        DIR *d = opendir(path); if (d) {
            struct dirent *de;
            while ((de = readdir(d))) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char child[4096]; snprintf(child, sizeof child, "%s/%s", path, de->d_name); rm_rf(child);
            }
            closedir(d);
        }
        return rmdir(path);
    }
    return unlink(path);
}
static int lin_trash(void *user, const uint16_t *path, int n) {
    (void)user; char *s = u_path(path, n); const char *home = getenv("HOME"); int rc = -1;
    if (home) {
        char files[1024], dest[1200], info[1200];
        snprintf(files, sizeof files, "%s/.local/share/Trash/files", home);
        char info_dir[1024]; snprintf(info_dir, sizeof info_dir, "%s/.local/share/Trash/info", home);
        mkdir(home, 0755);
        char parent[1024]; snprintf(parent, sizeof parent, "%s/.local", home); mkdir(parent, 0755);
        snprintf(parent, sizeof parent, "%s/.local/share", home); mkdir(parent, 0755);
        snprintf(parent, sizeof parent, "%s/.local/share/Trash", home); mkdir(parent, 0755);
        mkdir(files, 0755); mkdir(info_dir, 0755);
        const char *base = strrchr(s, '/'); base = base ? base + 1 : s;
        snprintf(dest, sizeof dest, "%s/%s", files, base);
        if (rename(s, dest) == 0) {
            snprintf(info, sizeof info, "%s/%s.trashinfo", info_dir, base);
            FILE *f = fopen(info, "w");
            if (f) { fprintf(f, "[Trash Info]\nPath=%s\n", s); fclose(f); }
            rc = 0;
        }
    }
    if (rc) rc = rm_rf(s);
    free(s); return rc;
}
static int lin_space(void *user, const uint16_t *path, int n, uint64_t *free_bytes, int *readonly) {
    (void)user; char *s = u_path(path, n); struct statvfs v; int rc = statvfs(s, &v);
    if (rc) { char *sl = strrchr(s, '/'); if (sl && sl != s) { *sl = 0; rc = statvfs(s, &v); } }
    free(s); if (rc) { *free_bytes = 0; *readonly = 1; return -1; }
    *free_bytes = (uint64_t)v.f_bavail * v.f_bsize; *readonly = (v.f_flag & ST_RDONLY) ? 1 : 0; return 0;
}
typedef struct { int fd; } Lfh;
static void *lin_open_read(void *user, const uint16_t *path, int n, uint64_t *size) {
    (void)user; char *s = u_path(path, n); int fd = open(s, O_RDONLY); free(s); if (fd < 0) return NULL;
    struct stat st; if (fstat(fd, &st)) { close(fd); return NULL; }
    *size = (uint64_t)st.st_size; Lfh *h = (Lfh *)calloc(1, sizeof *h); h->fd = fd; return h;
}
static int lin_read(void *fh, void *buf, uint32_t n, uint64_t off) { return pread(((Lfh *)fh)->fd, buf, n, (off_t)off) == (ssize_t)n ? 0 : -1; }
static void lin_close_read(void *fh) { close(((Lfh *)fh)->fd); free(fh); }
static void *lin_open_write(void *user, const uint16_t *path, int n) {
    (void)user; char *s = u_path(path, n); int fd = open(s, O_WRONLY | O_CREAT | O_TRUNC, 0644); free(s);
    if (fd < 0) return NULL; Lfh *h = (Lfh *)calloc(1, sizeof *h); h->fd = fd; return h;
}
static int lin_write(void *fh, const void *buf, uint32_t n, uint64_t off) { return pwrite(((Lfh *)fh)->fd, buf, n, (off_t)off) == (ssize_t)n ? 0 : -1; }
static void lin_close_write(void *fh) { close(((Lfh *)fh)->fd); free(fh); }
static int lin_meta(void *user, const uint16_t *path, int n, uint32_t mode, uint64_t ctime, uint64_t mtime) {
    (void)user; (void)ctime; char *s = u_path(path, n);
    if (mode) chmod(s, mode & 0777);
    struct timespec ts[2]; ts[0].tv_sec = (time_t)mtime; ts[0].tv_nsec = 0; ts[1] = ts[0];
    int rc = utimensat(AT_FDCWD, s, ts, 0); free(s); return rc;
}

static void *cable_thread(void *arg) {
    (void)arg;
    while (!g.stop) {
        if (g.sg < 0) {
            if (!open_cable()) { sleep(2); continue; }
            unsigned char ver[12] = {0}, bus[2] = {0};
            unsigned char cdb[16] = {0xF0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'O', 'T'};
            sg_raw(g.sg, cdb, ver, sizeof ver, 1);
            cdb[0] = 0xD8; cdb[2] = 2; sg_raw(g.sg, cdb, bus, sizeof bus, 1);
            cdb[1] = 1; cdb[2] = 5; cdb[4] = 0x7F; sg_raw(g.sg, cdb, NULL, 0, 2);
            char line[128]; snprintf(line, sizeof line, "Cable ready (firmware %.6s, USB %s).", (char *)ver + 6, bus[0] == 0x20 ? "2.0" : bus[0] == 0x11 ? "1.1" : "?");
            plog(&g, line); es_set_bus(g.es, bus[0], bus[1]);
        }
        int nap = es_serve_once(g.es);
        if (g.stop) break;
        if (nap < 0) { close_cable(); usleep(500000); continue; }
        if (nap > 0) usleep((useconds_t)nap * 1000);
    }
    close_cable(); return NULL;
}

static int map_path(const char *url, uint16_t *out, int *n) {
    EsRoot roots[48]; int nr = es_roots(g.es, roots, 48);
    return es_map_path(roots, nr, url, out, n);
}
static int lookup_wire(const uint16_t *path, int n, int *isdir, uint64_t *size, uint64_t *mtime) {
    EsRoot roots[48]; int nr = es_roots(g.es, roots, 48);
    for (int i = 0; i < nr; i++) if (es_u16_eq(path, n, roots[i].root, roots[i].nroot)) { *isdir = 1; *size = 0; *mtime = 0; return 0; }
    uint16_t par[1024]; int np = 0; es_parent(path, n, par, &np);
    uint16_t sep = es_is_windows_path(path, n) ? '\\' : '/';
    int cut = 0; for (int i = 0; i < n; i++) if (path[i] == sep) cut = i + 1;
    EsDent *d = NULL; int c = 0;
    if (es_list(g.es, par, np, &d, &c) != 0) { free(d); return -1; }
    int found = 0;
    for (int i = 0; i < c; i++) if (es_u16_eq(d[i].name, d[i].nname, path + cut, n - cut)) {
        *isdir = d[i].isdir; *size = d[i].size; *mtime = d[i].mtime; found = 1;
    }
    free(d); return found ? 0 : -1;
}

static int f_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi; memset(st, 0, sizeof *st); st->st_uid = getuid(); st->st_gid = getgid(); st->st_nlink = 1;
    if (!strcmp(path, "/")) { st->st_mode = S_IFDIR | 0555; st->st_nlink = 2; return 0; }
    uint16_t w[1024]; int n = 0; int m = map_path(path, w, &n);
    if (m < 0) return -ENOENT; if (m == 1) { st->st_mode = S_IFDIR | 0555; return 0; }
    int isdir = 0; uint64_t size = 0, mt = 0;
    if (lookup_wire(w, n, &isdir, &size, &mt) != 0) return -ENOENT;
    st->st_mode = isdir ? (S_IFDIR | 0755) : (S_IFREG | 0644); st->st_size = (off_t)size; st->st_mtime = (time_t)mt; st->st_nlink = isdir ? 2 : 1;
    return 0;
}
static int f_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)off; (void)fi; (void)flags; filler(buf, ".", NULL, 0, 0); filler(buf, "..", NULL, 0, 0);
    if (!strcmp(path, "/")) {
        EsRoot roots[48]; int nr = es_roots(g.es, roots, 48);
        for (int i = 0; i < nr; i++) { char id[256]; es_utf8_from_u16(roots[i].id, roots[i].nid, id, sizeof id); filler(buf, id, NULL, 0, 0); }
        return 0;
    }
    uint16_t w[1024]; int n = 0; if (map_path(path, w, &n) != 0) return -ENOENT;
    EsDent *d = NULL; int c = 0; if (es_list(g.es, w, n, &d, &c) != 0) { free(d); return -EIO; }
    for (int i = 0; i < c; i++) { char name[768]; es_utf8_from_u16(d[i].name, d[i].nname, name, sizeof name); filler(buf, name, NULL, 0, 0); }
    free(d); return 0;
}
typedef struct { int fd; char tmp[64]; int dirty; uint16_t path[1024]; int npath; } Of;
static int sink_fd(void *user, const void *buf, uint32_t n, uint64_t off) { return pwrite(*(int *)user, buf, n, (off_t)off) == (ssize_t)n ? 0 : -1; }
static int src_fd(void *user, void *buf, uint32_t n, uint64_t off) { return pread(*(int *)user, buf, n, (off_t)off) == (ssize_t)n ? 0 : -1; }
static Of *open_tmp(const uint16_t *path, int n, int download) {
    Of *o = (Of *)calloc(1, sizeof *o); snprintf(o->tmp, sizeof o->tmp, "/tmp/easysuite-XXXXXX");
    o->fd = mkstemp(o->tmp); if (o->fd < 0) { free(o); return NULL; }
    memcpy(o->path, path, (size_t)n * 2); o->npath = n;
    if (download && es_download(g.es, path, n, sink_fd, &o->fd) != 0) { close(o->fd); unlink(o->tmp); free(o); return NULL; }
    return o;
}
static int f_open(const char *path, struct fuse_file_info *fi) {
    uint16_t w[1024]; int n = 0; if (map_path(path, w, &n) != 0) return -ENOENT;
    Of *o = open_tmp(w, n, 1); if (!o) return -EIO; fi->fh = (uint64_t)(uintptr_t)o; return 0;
}
static int f_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode; uint16_t w[1024]; int n = 0; if (map_path(path, w, &n) != 0) return -ENOENT;
    Of *o = open_tmp(w, n, 0); if (!o) return -EIO; o->dirty = 1; fi->fh = (uint64_t)(uintptr_t)o; return 0;
}
static int f_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)path; Of *o = (Of *)(uintptr_t)fi->fh; ssize_t n = pread(o->fd, buf, size, off); return n < 0 ? -errno : (int)n;
}
static int f_write(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)path; Of *o = (Of *)(uintptr_t)fi->fh; ssize_t n = pwrite(o->fd, buf, size, off);
    if (n < 0) return -errno; o->dirty = 1; return (int)n;
}
static int f_release(const char *path, struct fuse_file_info *fi) {
    (void)path; Of *o = (Of *)(uintptr_t)fi->fh; int rc = 0;
    if (o->dirty) {
        struct stat st; if (fstat(o->fd, &st) == 0) rc = es_upload(g.es, o->path, o->npath, (uint64_t)st.st_size, src_fd, &o->fd) == 0 ? 0 : -EIO;
    }
    close(o->fd); unlink(o->tmp); free(o); return rc;
}
static int f_mkdir(const char *path, mode_t mode) {
    (void)mode; uint16_t w[1024]; int n = 0; if (map_path(path, w, &n) != 0) return -EINVAL;
    return es_mkdir(g.es, w, n) == 0 ? 0 : -EIO;
}
static int f_unlink(const char *path) {
    uint16_t w[1024]; int n = 0; if (map_path(path, w, &n) != 0) return -ENOENT;
    return es_delete_tree(g.es, w, n) == 0 ? 0 : -EIO;
}
static int f_rename(const char *from, const char *to, unsigned int flags) {
    if (flags) return -EINVAL;
    uint16_t a[1024], b[1024]; int na = 0, nb = 0;
    if (map_path(from, a, &na) != 0 || map_path(to, b, &nb) != 0) return -ENOENT;
    return es_rename(g.es, a, na, b, nb) == 0 ? 0 : -EIO;
}
static void *fuse_thread(void *arg) { (void)arg; fuse_loop(g.fuse); return NULL; }

enum { COL_NAME, COL_SIZE, COL_DATE, COL_KIND, COL_WIRE, COL_DIR, NCOL };
typedef struct { int kind; char a[1024], b[1024], local[1024]; int rc; EsDent *dents; int nd; } Job;
static void start_list(const char *wire);
static void fmt_size(uint64_t n, char *out, int cap) {
    if (n < 1024) snprintf(out, (size_t)cap, "%llu bytes", (unsigned long long)n);
    else if (n < 1024 * 1024) snprintf(out, (size_t)cap, "%.1f KB", n / 1024.0);
    else snprintf(out, (size_t)cap, "%.1f MB", n / (1024.0 * 1024));
}
static void fmt_time(uint64_t t, char *out, int cap) {
    if (!t) { out[0] = 0; return; } time_t tt = (time_t)t; struct tm tm; localtime_r(&tt, &tm);
    snprintf(out, (size_t)cap, "%04d-%02d-%02d %02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min);
}
static void fill_roots(void) {
    gtk_list_store_clear(g.store); g.ncur = 0;
    gtk_label_set_text(GTK_LABEL(g.pathlab), "EasySuite");
    EsRoot roots[48]; int nr = es_roots(g.es, roots, 48);
    for (int i = 0; i < nr; i++) {
        char name[512], wire[2048]; es_utf8_from_u16(roots[i].name, roots[i].nname, name, sizeof name);
        es_utf8_from_u16(roots[i].root, roots[i].nroot, wire, sizeof wire);
        GtkTreeIter it; gtk_list_store_append(g.store, &it);
        gtk_list_store_set(g.store, &it, COL_NAME, name, COL_SIZE, "", COL_DATE, "", COL_KIND, "Volume", COL_WIRE, wire, COL_DIR, 1, -1);
    }
}
static gboolean job_done(gpointer p) {
    Job *j = p; g.busy = 0;
    if (j->kind == 0 && j->rc == 0) {
        gtk_list_store_clear(g.store);
        int n = es_u16_from_utf8(j->a, g.cur, 1024); g.ncur = n;
        gtk_label_set_text(GTK_LABEL(g.pathlab), j->a[0] ? j->a : "EasySuite");
        for (int i = 0; i < j->nd; i++) {
            char name[768], size[64], when[32], wire[2048];
            es_utf8_from_u16(j->dents[i].name, j->dents[i].nname, name, sizeof name);
            uint16_t parent[1024], joined[1024]; int np = es_u16_from_utf8(j->a, parent, 1024), nj = 0;
            es_join(parent, np, j->dents[i].name, j->dents[i].nname, joined, &nj);
            es_utf8_from_u16(joined, nj, wire, sizeof wire);
            if (j->dents[i].isdir) size[0] = 0; else fmt_size(j->dents[i].size, size, sizeof size);
            fmt_time(j->dents[i].mtime, when, sizeof when);
            GtkTreeIter it; gtk_list_store_append(g.store, &it);
            gtk_list_store_set(g.store, &it, COL_NAME, name, COL_SIZE, size, COL_DATE, when, COL_KIND, j->dents[i].isdir ? "Folder" : "File", COL_WIRE, wire, COL_DIR, j->dents[i].isdir, -1);
        }
        gtk_label_set_text(GTK_LABEL(g.status), "Ready.");
    } else if (j->kind == 0) gtk_label_set_text(GTK_LABEL(g.status), "Couldn't open that folder.");
    else if (j->rc == 0) { gtk_label_set_text(GTK_LABEL(g.status), "Done."); if (g.ncur) { char cur[2048]; es_utf8_from_u16(g.cur, g.ncur, cur, sizeof cur); start_list(cur); } else fill_roots(); }
    else gtk_label_set_text(GTK_LABEL(g.status), "That didn't work.");
    free(j->dents); free(j); return G_SOURCE_REMOVE;
}
static void *job_thread(void *p) {
    Job *j = p; uint16_t a[1024], b[1024]; int na = j->a[0] ? es_u16_from_utf8(j->a, a, 1024) : 0, nb = j->b[0] ? es_u16_from_utf8(j->b, b, 1024) : 0;
    j->rc = -1;
    if (j->kind == 0) j->rc = es_list(g.es, a, na, &j->dents, &j->nd);
    else if (j->kind == 1) j->rc = es_mkdir(g.es, a, na);
    else if (j->kind == 2) j->rc = es_delete_tree(g.es, a, na);
    else if (j->kind == 3) j->rc = es_rename(g.es, a, na, b, nb);
    else if (j->kind == 4) {
        int fd = open(j->local, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) { j->rc = es_download(g.es, a, na, sink_fd, &fd); close(fd); if (j->rc) unlink(j->local); }
    } else if (j->kind == 5) {
        int fd = open(j->local, O_RDONLY); struct stat st;
        if (fd >= 0 && fstat(fd, &st) == 0) { j->rc = es_upload(g.es, a, na, (uint64_t)st.st_size, src_fd, &fd); close(fd); }
    }
    g_idle_add(job_done, j); return NULL;
}
static void start_job(Job *j) {
    if (g.busy || !es_logged_in(g.es)) { free(j); return; }
    g.busy = 1; gtk_label_set_text(GTK_LABEL(g.status), "Working…");
    pthread_t t; pthread_create(&t, NULL, job_thread, j); pthread_detach(t);
}
static void start_list(const char *wire) { Job *j = (Job *)calloc(1, sizeof *j); snprintf(j->a, sizeof j->a, "%s", wire); start_job(j); }

static int selected(char *wire, int cap, char *name, int ncap, int *isdir) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(g.list)); GtkTreeIter it;
    if (!gtk_tree_selection_get_selected(sel, NULL, &it)) return 0;
    char *w = NULL, *nm = NULL; int dir = 0;
    gtk_tree_model_get(GTK_TREE_MODEL(g.store), &it, COL_WIRE, &w, COL_NAME, &nm, COL_DIR, &dir, -1);
    if (wire && w) snprintf(wire, (size_t)cap, "%s", w);
    if (name && nm) snprintf(name, (size_t)ncap, "%s", nm);
    if (isdir) *isdir = dir; g_free(w); g_free(nm); return 1;
}
static char *ask(const char *title, const char *initial) {
    GtkWidget *d = gtk_dialog_new_with_buttons(title, GTK_WINDOW(g.window), GTK_DIALOG_MODAL, "_Cancel", GTK_RESPONSE_CANCEL, "_OK", GTK_RESPONSE_OK, NULL);
    GtkWidget *e = gtk_entry_new(); gtk_entry_set_text(GTK_ENTRY(e), initial ? initial : "");
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(d))), e, TRUE, TRUE, 8);
    gtk_widget_show_all(d); char *out = NULL;
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_OK) { const char *t = gtk_entry_get_text(GTK_ENTRY(e)); if (t && t[0]) out = strdup(t); }
    gtk_widget_destroy(d); return out;
}
static void on_up(GtkWidget *w, gpointer p) {
    (void)w; (void)p; if (g.busy || !g.ncur) return;
    EsRoot roots[48]; int nr = es_roots(g.es, roots, 48);
    for (int i = 0; i < nr; i++) if (es_u16_eq(g.cur, g.ncur, roots[i].root, roots[i].nroot)) { fill_roots(); return; }
    uint16_t par[1024]; int np = 0; es_parent(g.cur, g.ncur, par, &np);
    char s[2048]; es_utf8_from_u16(par, np, s, sizeof s); start_list(s);
}
static void on_refresh(GtkWidget *w, gpointer p) { (void)w; (void)p; if (!g.ncur) fill_roots(); else { char s[2048]; es_utf8_from_u16(g.cur, g.ncur, s, sizeof s); start_list(s); } }
static void on_mkdir(GtkWidget *w, gpointer p) {
    (void)w; (void)p; if (g.busy || !g.ncur) return; char *name = ask("New folder", ""); if (!name) return;
    uint16_t nm[256], joined[1024]; int nn = es_u16_from_utf8(name, nm, 256), nj = 0; free(name);
    es_join(g.cur, g.ncur, nm, nn, joined, &nj); char s[2048]; es_utf8_from_u16(joined, nj, s, sizeof s);
    Job *j = (Job *)calloc(1, sizeof *j); j->kind = 1; snprintf(j->a, sizeof j->a, "%s", s); start_job(j);
}
static void on_delete(GtkWidget *w, gpointer p) {
    (void)w; (void)p; char wire[2048]; if (g.busy || !g.ncur || !selected(wire, sizeof wire, NULL, 0, NULL)) return;
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(g.window), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK_CANCEL, "Delete the selected item?");
    int ok = gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_OK; gtk_widget_destroy(d); if (!ok) return;
    Job *j = (Job *)calloc(1, sizeof *j); j->kind = 2; snprintf(j->a, sizeof j->a, "%s", wire); start_job(j);
}
static void on_rename(GtkWidget *w, gpointer p) {
    (void)w; (void)p; char wire[2048], name[512]; if (g.busy || !g.ncur || !selected(wire, sizeof wire, name, sizeof name, NULL)) return;
    char *nn = ask("Rename", name); if (!nn) return;
    uint16_t u[256], joined[1024]; int nu = es_u16_from_utf8(nn, u, 256), nj = 0; free(nn);
    es_join(g.cur, g.ncur, u, nu, joined, &nj); char dest[2048]; es_utf8_from_u16(joined, nj, dest, sizeof dest);
    Job *j = (Job *)calloc(1, sizeof *j); j->kind = 3; snprintf(j->a, sizeof j->a, "%s", wire); snprintf(j->b, sizeof j->b, "%s", dest); start_job(j);
}
static void on_get(GtkWidget *w, gpointer p) {
    (void)w; (void)p; char wire[2048], name[512]; int dir = 0;
    if (g.busy || !selected(wire, sizeof wire, name, sizeof name, &dir) || dir) return;
    GtkWidget *d = gtk_file_chooser_dialog_new("Download", GTK_WINDOW(g.window), GTK_FILE_CHOOSER_ACTION_SAVE, "_Cancel", GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(d), name);
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        char *local = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(d));
        Job *j = (Job *)calloc(1, sizeof *j); j->kind = 4; snprintf(j->a, sizeof j->a, "%s", wire); snprintf(j->local, sizeof j->local, "%s", local); g_free(local); start_job(j);
    }
    gtk_widget_destroy(d);
}
static void on_put(GtkWidget *w, gpointer p) {
    (void)w; (void)p; if (g.busy || !g.ncur) return;
    GtkWidget *d = gtk_file_chooser_dialog_new("Upload", GTK_WINDOW(g.window), GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        char *local = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(d));
        const char *base = strrchr(local, '/'); base = base ? base + 1 : local;
        uint16_t nm[256], joined[1024]; int nn = es_u16_from_utf8(base, nm, 256), nj = 0;
        es_join(g.cur, g.ncur, nm, nn, joined, &nj); char dest[2048]; es_utf8_from_u16(joined, nj, dest, sizeof dest);
        Job *j = (Job *)calloc(1, sizeof *j); j->kind = 5; snprintf(j->a, sizeof j->a, "%s", dest); snprintf(j->local, sizeof j->local, "%s", local);
        g_free(local); start_job(j);
    }
    gtk_widget_destroy(d);
}
static void on_row(GtkTreeView *tv, GtkTreePath *path, GtkTreeViewColumn *col, gpointer p) {
    (void)tv; (void)col; (void)p; GtkTreeIter it; int dir = 0; char *wire = NULL;
    gtk_tree_model_get_iter(GTK_TREE_MODEL(g.store), &it, path);
    gtk_tree_model_get(GTK_TREE_MODEL(g.store), &it, COL_WIRE, &wire, COL_DIR, &dir, -1);
    if (dir && wire) start_list(wire); else on_get(NULL, NULL);
    g_free(wire);
}
static gboolean tick(gpointer p) {
    (void)p; if (g.busy) return G_SOURCE_CONTINUE;
    int in = g.es && es_logged_in(g.es); static int was = -1;
    if (in != was) { was = in; if (in) fill_roots(); else { gtk_list_store_clear(g.store); gtk_label_set_text(GTK_LABEL(g.status), "Waiting for the other computer…"); g.ncur = 0; } }
    return G_SOURCE_CONTINUE;
}
static void on_destroy(GtkWidget *w, gpointer p) { (void)w; (void)p; g.stop = 1; if (g.es) es_request_stop(g.es); if (g.fuse) fuse_exit(g.fuse); gtk_main_quit(); }

int main(int argc, char **argv) {
    gtk_init(&argc, &argv); g.sg = -1;
    pthread_mutex_init(&g.mu, NULL); pthread_mutex_init(&g.op, NULL); pthread_cond_init(&g.cv, NULL);
    EsHooks hooks; memset(&hooks, 0, sizeof hooks);
    hooks.user = &g; hooks.lock = plock; hooks.unlock = punlock; hooks.wait = pwait; hooks.wake = pwake;
    hooks.op_lock = poplock; hooks.op_unlock = popunlock; hooks.now_ms = pnow; hooks.log = plog; hooks.scsi = pscsi;
    hooks.fs.user = &g; hooks.fs.volumes = lin_volumes; hooks.fs.list_dir = lin_list; hooks.fs.stat_path = lin_stat;
    hooks.fs.mkdir = lin_mkdir; hooks.fs.rename = lin_rename; hooks.fs.trash = lin_trash; hooks.fs.space = lin_space;
    hooks.fs.open_read = lin_open_read; hooks.fs.read_at = lin_read; hooks.fs.close_read = lin_close_read;
    hooks.fs.open_write = lin_open_write; hooks.fs.write_at = lin_write; hooks.fs.close_write = lin_close_write; hooks.fs.set_meta = lin_meta;
    g.es = es_new(ES_OS_LINUX, 1, &hooks);

    g.window = gtk_window_new(GTK_WINDOW_TOPLEVEL); gtk_window_set_title(GTK_WINDOW(g.window), "EasySuite");
    gtk_window_set_default_size(GTK_WINDOW(g.window), 960, 600);
    g_signal_connect(g.window, "destroy", G_CALLBACK(on_destroy), NULL);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4); gtk_container_add(GTK_CONTAINER(g.window), box);
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    const char *labels[] = {"Up", "Refresh", "New folder", "Delete", "Rename", "Download", "Upload"};
    void (*fns[])(GtkWidget *, gpointer) = {on_up, on_refresh, on_mkdir, on_delete, on_rename, on_get, on_put};
    for (int i = 0; i < 7; i++) { GtkWidget *b = gtk_button_new_with_label(labels[i]); g_signal_connect(b, "clicked", G_CALLBACK(fns[i]), NULL); gtk_box_pack_start(GTK_BOX(bar), b, FALSE, FALSE, 0); }
    gtk_box_pack_start(GTK_BOX(box), bar, FALSE, FALSE, 0);
    g.pathlab = gtk_label_new("EasySuite"); gtk_label_set_xalign(GTK_LABEL(g.pathlab), 0);
    gtk_box_pack_start(GTK_BOX(box), g.pathlab, FALSE, FALSE, 0);
    g.store = gtk_list_store_new(NCOL, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT);
    g.list = gtk_tree_view_new_with_model(GTK_TREE_MODEL(g.store));
    const char *cols[] = {"Name", "Size", "Modified", "Kind"};
    for (int i = 0; i < 4; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(cols[i], r, "text", i, NULL);
        gtk_tree_view_column_set_resizable(c, TRUE); gtk_tree_view_column_set_min_width(c, i == 0 ? 280 : 100);
        gtk_tree_view_append_column(GTK_TREE_VIEW(g.list), c);
    }
    g_signal_connect(g.list, "row-activated", G_CALLBACK(on_row), NULL);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL); gtk_container_add(GTK_CONTAINER(scroll), g.list);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);
    g.status = gtk_label_new("Waiting for the EasySuite cable…"); gtk_label_set_xalign(GTK_LABEL(g.status), 0);
    gtk_box_pack_start(GTK_BOX(box), g.status, FALSE, FALSE, 0);
    gtk_widget_show_all(g.window);
    g_timeout_add(800, tick, NULL);

    const char *home = getenv("HOME"); char mnt[1024];
    snprintf(mnt, sizeof mnt, "%s/EasySuite", home ? home : "/tmp"); mkdir(mnt, 0755);
    struct fuse_operations ops; memset(&ops, 0, sizeof ops);
    ops.getattr = f_getattr; ops.readdir = f_readdir; ops.open = f_open; ops.read = f_read; ops.write = f_write;
    ops.release = f_release; ops.mkdir = f_mkdir; ops.unlink = f_unlink; ops.rmdir = f_unlink; ops.rename = f_rename; ops.create = f_create;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, "easysuite"); fuse_opt_add_arg(&args, "-f");
    fuse_opt_add_arg(&args, "-o"); fuse_opt_add_arg(&args, "auto_unmount,attr_timeout=0,fsname=EasySuite");
    g.fuse = fuse_new(&args, &ops, sizeof ops, NULL);
    if (g.fuse && fuse_mount(g.fuse, mnt) == 0) {
        pthread_t ft; pthread_create(&ft, NULL, fuse_thread, NULL); pthread_detach(ft);
        char note[1200]; snprintf(note, sizeof note, "The other computer will also be at %s", mnt); plog(&g, note);
    } else plog(&g, "FUSE mount failed. The window still works. Check that fusermount3 is allowed.");

    pthread_t cable; pthread_create(&cable, NULL, cable_thread, NULL);
    gtk_main();
    g.stop = 1; es_request_stop(g.es); pthread_join(cable, NULL);
    if (g.fuse) { fuse_unmount(g.fuse); fuse_destroy(g.fuse); }
    es_free(g.es); return 0;
}
