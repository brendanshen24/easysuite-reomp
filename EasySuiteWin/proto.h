/* Shared EasySuite cable protocol for the Windows and Linux peers.
   Packet headers are always little-endian. Payload endianness follows the
   sender: OS code < 8 writes little-endian (Windows), OS code >= 8 writes
   big-endian (Mac and Linux). Linux uses OS code 0x14 and POSIX paths. */
#ifndef EASYSUITE_PROTO_H
#define EASYSUITE_PROTO_H

#include <stddef.h>
#include <stdint.h>

enum {
    ES_PKT_SIZE = 0x10000,
    ES_PKT_HDR = 0x14,
    ES_PKT_MAX = 0xFFEC,
    ES_FILE_BLOCK = 0x9F81F,
    ES_OS_WINDOWS = 5,
    ES_OS_MAC = 0x13,
    ES_OS_LINUX = 0x14
};

typedef struct EsDent {
    int isdir;
    uint64_t size, mtime, ctime;
    uint16_t name[256];
    int nname;
} EsDent;

typedef struct EsRoot {
    uint16_t id[128];
    int nid;
    uint16_t name[260];
    int nname;
    uint16_t root[1024];
    int nroot;
} EsRoot;

typedef struct EsVol {
    uint8_t letter, type;
    uint16_t name[260];
    int nname;
    uint16_t path[1024];
    int npath;
} EsVol;

/* Local filesystem behind the server half. Paths are host-endian UTF-16.
   Return 0 on success unless noted. Callbacks run on the cable thread. */
typedef struct EsFs {
    void *user;
    int (*volumes)(void *user, EsVol **out, int *count);
    int (*list_dir)(void *user, const uint16_t *path, int n, EsDent **out, int *count);
    int (*stat_path)(void *user, const uint16_t *path, int n, int *isdir, uint64_t *size, uint64_t *mtime);
    int (*mkdir)(void *user, const uint16_t *path, int n);
    int (*rename)(void *user, const uint16_t *from, int nf, const uint16_t *to, int nt);
    int (*trash)(void *user, const uint16_t *path, int n);
    int (*space)(void *user, const uint16_t *path, int n, uint64_t *free_bytes, int *readonly);
    void *(*open_read)(void *user, const uint16_t *path, int n, uint64_t *size);
    int (*read_at)(void *fh, void *buf, uint32_t n, uint64_t off);
    void (*close_read)(void *fh);
    void *(*open_write)(void *user, const uint16_t *path, int n);
    int (*write_at)(void *fh, const void *buf, uint32_t n, uint64_t off);
    void (*close_write)(void *fh);
    int (*set_meta)(void *user, const uint16_t *path, int n, uint32_t mode, uint64_t ctime, uint64_t mtime);
} EsFs;

typedef int (*EsReadFn)(void *user, void *buf, uint32_t n, uint64_t off);
typedef int (*EsWriteFn)(void *user, const void *buf, uint32_t n, uint64_t off);

typedef struct EsHooks {
    void *user;
    void (*lock)(void *user);
    void (*unlock)(void *user);
    void (*wait)(void *user, int timeout_ms); /* proto lock is held; release it, wait, reacquire */
    void (*wake)(void *user);                 /* proto lock is held */
    void (*op_lock)(void *user);              /* one client operation at a time; not the proto lock */
    void (*op_unlock)(void *user);
    uint32_t (*now_ms)(void);
    void (*log)(void *user, const char *msg);
    /* dir: 0 host->device, 1 device->host, 2 none. Return 0, an OTi code, or -1. */
    int (*scsi)(void *user, uint8_t op, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4,
                void *buf, uint32_t len, int dir);
    EsFs fs;
} EsHooks;

typedef struct Es Es;

Es *es_new(int our_os, int write_be, const EsHooks *hooks);
void es_free(Es *es);
void es_set_bus(Es *es, uint8_t ours, uint8_t remote);
void es_request_stop(Es *es);
int es_stopped(Es *es);

/* One poll. Returns milliseconds to sleep, or -1 if the cable is gone. */
int es_serve_once(Es *es);

int es_logged_in(Es *es);
int es_remote_os(Es *es);
int es_remote_be(Es *es);
const char *es_peer_name(int remote_os);
int es_roots(Es *es, EsRoot *out, int cap);

int es_list(Es *es, const uint16_t *path, int n, EsDent **out, int *count);
int es_mkdir(Es *es, const uint16_t *path, int n);
int es_rename(Es *es, const uint16_t *from, int nf, const uint16_t *to, int nt);
int es_delete_tree(Es *es, const uint16_t *path, int n);
int es_download(Es *es, const uint16_t *path, int n, EsWriteFn write, void *user);
int es_upload(Es *es, const uint16_t *path, int n, uint64_t size, EsReadFn read, void *user);

int es_is_windows_path(const uint16_t *s, int n);
void es_parent(const uint16_t *s, int n, uint16_t *out, int *nout);
void es_join(const uint16_t *dir, int nd, const uint16_t *name, int nn, uint16_t *out, int *nout);
int es_u16_from_utf8(const char *s, uint16_t *out, int cap);
void es_utf8_from_u16(const uint16_t *s, int n, char *out, int cap);
int es_u16_eq(const uint16_t *a, int na, const uint16_t *b, int nb);
int es_u16_from_ascii(const char *s, uint16_t *out, int cap);

/* Map "/VolumeId/dir/file" onto a wire path. Returns 0, 1 if `url` is the share
   root (no wire path), or -1 if it is outside the volumes. */
int es_map_path(const EsRoot *roots, int nroots, const char *url, uint16_t *out, int *nout);

#endif
