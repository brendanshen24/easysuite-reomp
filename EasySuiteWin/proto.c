#include "proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef struct Tx {
    struct Tx *next;
    uint8_t b[ES_PKT_SIZE];
} Tx;

typedef struct Rx {
    int used;
    uint32_t session, got, total;
    uint8_t *buf;
    size_t len, cap;
} Rx;

typedef struct DlFile {
    uint32_t fid;
    uint16_t *path;
    int npath;
} DlFile;

typedef struct Job {
    uint32_t session;
    DlFile *files;
    int n, idx;
    void *fh;
    uint64_t size, sent;
    uint32_t blocks, block;
} Job;

typedef struct UpFile {
    uint32_t fid;
    uint16_t *path;
    int npath;
} UpFile;

struct Es {
    EsHooks hooks;
    int our_os, write_be, remote_os, read_be;
    int logged_in, stop, failures, cont_tx;
    uint16_t bus;
    unsigned booking, max_tx;
    uint32_t pkt_counter, session_ctr, conn_gen, activity, login_ms;
    int login_sent;
    Tx *tx_head, *tx_tail;
    int tx_count;
    Rx rx[8];
    uint8_t *scratch;
    Job *jobs;
    int njobs;
    uint32_t up_session;
    UpFile *up_files;
    int up_n;
    void *up_fh;
    uint16_t *up_path;
    int up_npath;
    int up_cancel;
    uint8_t got[256], res[256];
    int want_dir, want_a8;
    uint8_t *dir_msg, *a8;
    size_t dir_len, a8_len;
    uint32_t dl_session;
    EsWriteFn dl_write;
    void *dl_user;
    uint64_t dl_off;
    int dl_done, dl_failed;
    uint32_t ul_session;
    int ul_failed;
    EsRoot roots[48];
    int nroots;
    uint8_t *vol;
    size_t vol_len;
    int said_wait;
};

static void es_lock(Es *es) { if (es->hooks.lock) es->hooks.lock(es->hooks.user); }
static void es_unlock(Es *es) { if (es->hooks.unlock) es->hooks.unlock(es->hooks.user); }
static void es_wake(Es *es) { if (es->hooks.wake) es->hooks.wake(es->hooks.user); }
static uint32_t es_now(Es *es) { return es->hooks.now_ms ? es->hooks.now_ms() : 0; }

static void es_log(Es *es, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (es->hooks.log) es->hooks.log(es->hooks.user, buf);
}

static void b16raw(uint8_t *p, int be, uint16_t v) {
    if (be) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
    else { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
}
static void b32raw(uint8_t *p, int be, uint32_t v) {
    if (be) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
    else { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
}
static uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

typedef struct { uint8_t *b; size_t n, cap; } Buf;
static void buf_add(Buf *b, const void *p, size_t n) {
    if (b->n + n > b->cap) {
        size_t c = b->cap ? b->cap * 2 : 64;
        while (c < b->n + n) c *= 2;
        uint8_t *nb = (uint8_t *)realloc(b->b, c);
        if (!nb) return;
        b->b = nb; b->cap = c;
    }
    if (p && n) memcpy(b->b + b->n, p, n);
    b->n += n;
}
static void buf_u8(Buf *b, uint8_t v) { buf_add(b, &v, 1); }
static void buf_u16(Buf *b, int be, uint16_t v) { uint8_t p[2]; b16raw(p, be, v); buf_add(b, p, 2); }
static void buf_u32(Buf *b, int be, uint32_t v) { uint8_t p[4]; b32raw(p, be, v); buf_add(b, p, 4); }
static void buf_u64(Buf *b, int be, uint64_t v) {
    buf_u32(b, be, be ? (uint32_t)(v >> 32) : (uint32_t)v);
    buf_u32(b, be, be ? (uint32_t)v : (uint32_t)(v >> 32));
}
static void buf_utf16(Buf *b, int be, const uint16_t *s, int n) {
    for (int i = 0; i < n; i++) buf_u16(b, be, s[i]);
}

typedef struct { const uint8_t *p, *end; int bad; } Rd;
static const uint8_t *take(Rd *r, size_t n) {
    if (r->bad || (size_t)(r->end - r->p) < n) { r->bad = 1; return NULL; }
    const uint8_t *q = r->p; r->p += n; return q;
}
static uint16_t ru16(Rd *r, int be) {
    const uint8_t *q = take(r, 2);
    if (!q) return 0;
    return be ? (uint16_t)((q[0] << 8) | q[1]) : (uint16_t)(q[0] | (q[1] << 8));
}
static uint32_t ru32(Rd *r, int be) {
    const uint8_t *q = take(r, 4);
    if (!q) return 0;
    return be ? ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16) | ((uint32_t)q[2] << 8) | q[3]
              : (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
}
static uint64_t ru64(Rd *r, int be) {
    uint64_t hi = ru32(r, be), lo = ru32(r, be);
    return be ? (hi << 32) | lo : (lo << 32) | hi;
}
static int ru16str(Rd *r, int be, uint16_t *dst, int cap, uint32_t nbytes) {
    if (nbytes & 1u) { r->bad = 1; return 0; }
    const uint8_t *q = take(r, nbytes);
    if (!q) return 0;
    int n = (int)(nbytes / 2);
    if (n > cap - 1) { r->bad = 1; return 0; }
    for (int i = 0; i < n; i++) {
        dst[i] = be ? (uint16_t)((q[i * 2] << 8) | q[i * 2 + 1]) : (uint16_t)(q[i * 2] | (q[i * 2 + 1] << 8));
    }
    dst[n] = 0;
    return n;
}

int es_u16_from_ascii(const char *s, uint16_t *out, int cap) {
    int n = 0;
    while (s[n] && n < cap - 1) { out[n] = (uint8_t)s[n]; n++; }
    out[n] = 0;
    return n;
}
int es_u16_eq(const uint16_t *a, int na, const uint16_t *b, int nb) {
    if (na != nb) return 0;
    for (int i = 0; i < na; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static uint32_t utf8_cp(const char **ps) {
    const uint8_t *u = (const uint8_t *)*ps;
    uint32_t cp; int n = 1;
    if (u[0] < 0x80) cp = u[0];
    else if ((u[0] & 0xe0) == 0xc0 && u[1]) { cp = ((u[0] & 0x1f) << 6) | (u[1] & 0x3f); n = 2; }
    else if ((u[0] & 0xf0) == 0xe0 && u[1] && u[2]) { cp = ((u[0] & 0x0f) << 12) | ((u[1] & 0x3f) << 6) | (u[2] & 0x3f); n = 3; }
    else if ((u[0] & 0xf8) == 0xf0 && u[1] && u[2] && u[3]) {
        cp = ((u[0] & 7) << 18) | ((u[1] & 0x3f) << 12) | ((u[2] & 0x3f) << 6) | (u[3] & 0x3f); n = 4;
    } else cp = 0xFFFD;
    *ps += n;
    return cp;
}
int es_u16_from_utf8(const char *s, uint16_t *out, int cap) {
    int n = 0;
    while (*s && n < cap - 1) {
        uint32_t cp = utf8_cp(&s);
        if (cp > 0x10FFFF) cp = 0xFFFD;
        if (cp > 0xFFFF) {
            if (n + 2 >= cap) break;
            cp -= 0x10000;
            out[n++] = (uint16_t)(0xD800 + (cp >> 10));
            out[n++] = (uint16_t)(0xDC00 + (cp & 0x3FF));
        } else out[n++] = (uint16_t)cp;
    }
    out[n] = 0;
    return n;
}
void es_utf8_from_u16(const uint16_t *s, int n, char *out, int cap) {
    int o = 0;
    for (int i = 0; i < n && o < cap - 1; i++) {
        uint32_t cp = s[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < n && s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (s[++i] - 0xDC00);
        }
        if (cp < 0x80) { if (o + 1 >= cap) break; out[o++] = (char)cp; }
        else if (cp < 0x800) { if (o + 2 >= cap) break; out[o++] = (char)(0xc0 | (cp >> 6)); out[o++] = (char)(0x80 | (cp & 0x3f)); }
        else if (cp < 0x10000) {
            if (o + 3 >= cap) break;
            out[o++] = (char)(0xe0 | (cp >> 12)); out[o++] = (char)(0x80 | ((cp >> 6) & 0x3f)); out[o++] = (char)(0x80 | (cp & 0x3f));
        } else {
            if (o + 4 >= cap) break;
            out[o++] = (char)(0xf0 | (cp >> 18)); out[o++] = (char)(0x80 | ((cp >> 12) & 0x3f));
            out[o++] = (char)(0x80 | ((cp >> 6) & 0x3f)); out[o++] = (char)(0x80 | (cp & 0x3f));
        }
    }
    out[o] = 0;
}

int es_is_windows_path(const uint16_t *s, int n) {
    for (int i = 0; i < n; i++) if (s[i] == '\\') return 1;
    return n >= 2 && s[1] == ':';
}
static uint16_t path_sep(const uint16_t *s, int n) { return es_is_windows_path(s, n) ? '\\' : '/'; }
void es_parent(const uint16_t *s, int n, uint16_t *out, int *nout) {
    uint16_t sep = path_sep(s, n);
    int cut = -1;
    for (int i = 0; i < n; i++) if (s[i] == sep) cut = i;
    if (sep == '\\') {
        int keep = (cut < 0 || cut <= 2) ? (n >= 3 ? 3 : n) : cut;
        if (keep > 1023) keep = 1023;
        memcpy(out, s, (size_t)keep * 2); out[keep] = 0; *nout = keep;
        return;
    }
    if (n <= 1) { out[0] = '/'; out[1] = 0; *nout = 1; return; }
    if (cut <= 0) { out[0] = '/'; out[1] = 0; *nout = 1; return; }
    memcpy(out, s, (size_t)cut * 2); out[cut] = 0; *nout = cut;
}
void es_join(const uint16_t *dir, int nd, const uint16_t *name, int nn, uint16_t *out, int *nout) {
    uint16_t sep = path_sep(dir, nd);
    int n = 0;
    if (nd == 1 && dir[0] == '/') {
        out[n++] = '/';
    } else {
        if (nd > 1020) nd = 1020;
        memcpy(out, dir, (size_t)nd * 2); n = nd;
        if (nd == 0 || dir[nd - 1] != sep) out[n++] = sep;
    }
    if (n + nn > 1023) nn = 1023 - n;
    if (nn < 0) nn = 0;
    memcpy(out + n, name, (size_t)nn * 2);
    n += nn; out[n] = 0; *nout = n;
}

static void u16_copy(uint16_t *dst, int cap, int *nout, const uint16_t *src, int n) {
    if (n > cap - 1) n = cap - 1;
    if (n < 0) n = 0;
    memcpy(dst, src, (size_t)n * 2); dst[n] = 0; *nout = n;
}

const char *es_peer_name(int remote_os) {
    if (remote_os == ES_OS_LINUX) return "Linux";
    if (remote_os >= 8) return "Mac";
    if (remote_os) return "Windows";
    return "the other computer";
}

int es_map_path(const EsRoot *roots, int nroots, const char *url, uint16_t *out, int *nout) {
    if (!url || url[0] != '/') return -1;
    const char *p = url;
    char parts[64][256];
    int np = 0;
    while (*p && np < 64) {
        while (*p == '/') p++;
        if (!*p) break;
        int k = 0;
        while (*p && *p != '/' && k < 255) parts[np][k++] = *p++;
        parts[np][k] = 0;
        if (k == 0) break;
        if (!strcmp(parts[np], "..") || strchr(parts[np], '\\')) return -1;
        np++;
    }
    if (!np) { *nout = 0; out[0] = 0; return 1; }
    const EsRoot *root = NULL;
    for (int i = 0; i < nroots; i++) {
        char id[256];
        es_utf8_from_u16(roots[i].id, roots[i].nid, id, sizeof id);
        if (!strcmp(id, parts[0])) root = &roots[i];
    }
    if (!root) return -1;
    if (np == 1) { u16_copy(out, 1024, nout, root->root, root->nroot); return 0; }
    uint16_t cur[1024]; int nc = root->nroot;
    if (nc > 1023) nc = 1023;
    memcpy(cur, root->root, (size_t)nc * 2); cur[nc] = 0;
    for (int i = 1; i < np; i++) {
        uint16_t name[256]; int nn = es_u16_from_utf8(parts[i], name, 256);
        uint16_t next[1024]; int nx = 0;
        es_join(cur, nc, name, nn, next, &nx);
        memcpy(cur, next, (size_t)(nx + 1) * 2); nc = nx;
    }
    u16_copy(out, 1024, nout, cur, nc);
    return 0;
}

Es *es_new(int our_os, int write_be, const EsHooks *hooks) {
    Es *es = (Es *)calloc(1, sizeof *es);
    if (!es) return NULL;
    if (hooks) es->hooks = *hooks;
    es->our_os = our_os;
    es->write_be = write_be;
    es->read_be = 0;
    es->booking = 15;
    es->max_tx = 45;
    es->session_ctr = 0x10000000u ^ (es_now(es) & 0x0fffffffu);
    es->scratch = (uint8_t *)malloc(ES_PKT_SIZE);
    return es;
}
static void free_tx(Es *es) {
    while (es->tx_head) { Tx *n = es->tx_head->next; free(es->tx_head); es->tx_head = n; }
    es->tx_tail = NULL; es->tx_count = 0;
}
static void drop_jobs(Es *es) {
    for (int i = 0; i < es->njobs; i++) {
        if (es->jobs[i].fh && es->hooks.fs.close_read) es->hooks.fs.close_read(es->jobs[i].fh);
        for (int f = 0; f < es->jobs[i].n; f++) free(es->jobs[i].files[f].path);
        free(es->jobs[i].files);
    }
    free(es->jobs); es->jobs = NULL; es->njobs = 0;
}
static void drop_up(Es *es) {
    if (es->up_fh && es->hooks.fs.close_write) es->hooks.fs.close_write(es->up_fh);
    es->up_fh = NULL;
    for (int i = 0; i < es->up_n; i++) free(es->up_files[i].path);
    free(es->up_files); es->up_files = NULL; es->up_n = 0;
    free(es->up_path); es->up_path = NULL; es->up_npath = 0;
}
void es_free(Es *es) {
    if (!es) return;
    free_tx(es);
    drop_jobs(es);
    drop_up(es);
    for (int i = 0; i < 8; i++) free(es->rx[i].buf);
    free(es->dir_msg); free(es->a8); free(es->vol); free(es->scratch);
    free(es);
}
void es_set_bus(Es *es, uint8_t ours, uint8_t remote) {
    es_lock(es);
    es->bus = (uint16_t)((ours << 8) | remote);
    es->booking = 15; es->max_tx = 45;
    if (es->remote_os && es->bus == 0x2020) es->booking = (es->remote_os >= 3 && es->remote_os <= 4) ? 50 : 100;
    es->max_tx = es->booking * 3;
    es_unlock(es);
}
void es_request_stop(Es *es) {
    es_lock(es); es->stop = 1; es->conn_gen++; es_wake(es); es_unlock(es);
}
int es_stopped(Es *es) { return es->stop; }

static uint32_t new_session(Es *es) { return ++es->session_ctr; }

static void queue_msg(Es *es, const uint8_t *msg, size_t len, uint32_t session) {
    size_t total = len ? (len + ES_PKT_MAX - 1) / ES_PKT_MAX : 1;
    for (size_t i = 0; i < total; i++) {
        size_t off = i * ES_PKT_MAX, n = len - off;
        if (n > ES_PKT_MAX) n = ES_PKT_MAX;
        Tx *t = (Tx *)calloc(1, sizeof *t);
        if (!t) return;
        wr_le32(t->b + 0, es->pkt_counter++);
        wr_le32(t->b + 4, session);
        wr_le32(t->b + 8, (uint32_t)i);
        wr_le32(t->b + 12, (uint32_t)total);
        wr_le32(t->b + 16, (uint32_t)n);
        if (n && msg) memcpy(t->b + ES_PKT_HDR, msg + off, n);
        if (es->tx_tail) es->tx_tail->next = t; else es->tx_head = t;
        es->tx_tail = t; es->tx_count++;
    }
}
static void queue_buf(Es *es, Buf *b, uint32_t session) { queue_msg(es, b->b, b->n, session); free(b->b); b->b = NULL; b->n = b->cap = 0; }

static void adjust_booking(Es *es) {
    if (es->bus == 0x2020) es->booking = (es->remote_os >= 3 && es->remote_os <= 4) ? 50 : 100;
    es->max_tx = es->booking * 3;
}

static void reply_result(Es *es, uint8_t cmd, uint8_t result, uint32_t err, uint32_t sess) {
    Buf b = {0};
    buf_u8(&b, 0xA1); buf_u8(&b, cmd); buf_u8(&b, result);
    buf_u32(&b, es->write_be, sess); buf_u32(&b, es->write_be, err);
    buf_u64(&b, es->write_be, 0); buf_u8(&b, 0); buf_u32(&b, es->write_be, 0);
    queue_buf(es, &b, new_session(es));
}
static void reply_error(Es *es, uint8_t cmd, uint32_t session, uint32_t err, int with_id, uint32_t fid) {
    const char *text = err ? "Error" : "Overwriting File was Readonly or Locked";
    uint16_t u[64]; int n = es_u16_from_ascii(text, u, 64);
    Buf b = {0};
    buf_u8(&b, cmd); buf_u32(&b, es->write_be, session); buf_u32(&b, es->write_be, err);
    if (with_id) buf_u32(&b, es->write_be, fid);
    buf_add(&b, "ErrStr", 6); buf_u32(&b, es->write_be, (uint32_t)(n * 2)); buf_utf16(&b, es->write_be, u, n);
    queue_buf(es, &b, new_session(es));
}
static void reply_finish(Es *es, uint32_t session) {
    Buf b = {0}; buf_u8(&b, 0xA7); buf_u32(&b, es->write_be, session); queue_buf(es, &b, new_session(es));
}

static int append_entry(Es *es, Buf *out, const EsDent *d) {
    int nb = d->nname * 2;
    if (nb > 512) nb = 512;
    if (nb < 0) nb = 0;
    buf_u32(out, es->write_be, d->isdir ? 0x10 : 0x20);
    buf_u64(out, es->write_be, d->ctime);
    buf_u64(out, es->write_be, d->mtime);
    buf_u64(out, es->write_be, d->mtime);
    buf_u64(out, es->write_be, d->size);
    buf_u32(out, es->write_be, (uint32_t)(d->nname * 2 > 512 ? 512 : d->nname * 2));
    int chars = nb / 2;
    buf_utf16(out, es->write_be, d->name, chars);
    if (512 - nb > 0) {
        uint8_t *z = (uint8_t *)calloc(1, (size_t)(512 - nb));
        buf_add(out, z, (size_t)(512 - nb));
        free(z);
    }
    return 1;
}

static void reply_dir(Es *es, const uint16_t *path, int npath, uint32_t pkt_session) {
    EsDent *dents = NULL; int count = 0;
    int rc = es->hooks.fs.list_dir ? es->hooks.fs.list_dir(es->hooks.fs.user, path, npath, &dents, &count) : -1;
    Buf items = {0}; int n = 0;
    if (rc == 0) {
        for (int i = 0; i < count && n < 0xFFFF; i++) {
            if (!dents[i].nname) continue;
            if (dents[i].nname && dents[i].name[0] == '.') continue;
            append_entry(es, &items, &dents[i]); n++;
        }
    }
    free(dents);
    Buf m = {0}; buf_u8(&m, 0xA2); buf_u16(&m, es->write_be, (uint16_t)n); buf_add(&m, items.b, items.n); free(items.b);
    queue_buf(es, &m, pkt_session);
}

static void reply_volumes(Es *es) {
    EsVol *vols = NULL; int count = 0;
    if (es->hooks.fs.volumes) es->hooks.fs.volumes(es->hooks.fs.user, &vols, &count);
    if (count > 64) count = 64;
    Buf m = {0};
    buf_u8(&m, 0xA4);
    uint8_t le[2] = {(uint8_t)count, (uint8_t)(count >> 8)};
    buf_add(&m, le, 2);
    for (int i = 0; i < count; i++) { buf_u8(&m, vols[i].letter ? vols[i].letter : 'A'); buf_u8(&m, vols[i].type ? vols[i].type : 0x12); }
    for (int i = 0; i < count; i++) {
        int nb = vols[i].nname * 2, pb = vols[i].npath * 2;
        if (nb < 0) nb = 0;
        if (pb < 0) pb = 0;
        if (nb > 65534) nb = 65534;
        if (pb > 65534) pb = 65534;
        buf_u16(&m, es->write_be, (uint16_t)nb); buf_utf16(&m, es->write_be, vols[i].name, nb / 2);
        buf_u16(&m, es->write_be, (uint16_t)pb); buf_utf16(&m, es->write_be, vols[i].path, pb / 2);
    }
    free(vols);
    queue_buf(es, &m, new_session(es));
}

static void apply_vols(Es *es) {
    if (!es->vol || es->vol_len < 3 || !es->remote_os) return;
    const uint8_t *d = es->vol;
    uint16_t c = (uint16_t)(d[1] | (d[2] << 8));
    if ((size_t)(3 + 2 * c) > es->vol_len) return;
    Rd r = {d + 3 + 2 * c, d + es->vol_len, 0};
    EsRoot roots[48]; int nr = 0;
    char seen[48][128]; int nseen = 0;
    for (uint16_t i = 0; i < c && nr < 48; i++) {
        unsigned char letter = d[3 + 2 * i];
        uint16_t name[260], path[1024]; int nn = 0, np = 0;
        if (r.p < r.end && !r.bad) {
            uint16_t nl = ru16(&r, es->read_be); nn = ru16str(&r, es->read_be, name, 260, nl);
            uint16_t pl = ru16(&r, es->read_be); np = ru16str(&r, es->read_be, path, 1024, pl);
            if (r.bad) nn = np = 0;
        }
        uint16_t root[1024], ident[128], shown[260]; int nroot = 0, ni = 0, ns = 0;
        if (es->remote_os < 8) {
            if (letter < 'C' || letter > 'Z') continue;
            ident[0] = letter; ident[1] = 0; ni = 1;
            root[0] = letter; root[1] = ':'; root[2] = '\\'; root[3] = 0; nroot = 3;
            if (nn) u16_copy(shown, 260, &ns, name, nn); else u16_copy(shown, 260, &ns, ident, 1);
        } else if (np) {
            u16_copy(root, 1024, &nroot, path, np);
            if (nn) u16_copy(shown, 260, &ns, name, nn);
            else {
                int cut = 0;
                for (int k = 0; k < np; k++) if (path[k] == '/' || path[k] == '\\') cut = k + 1;
                if (cut >= np) { shown[0] = 'V'; shown[1] = 0; ns = 1; }
                else u16_copy(shown, 260, &ns, path + cut, np - cut);
            }
            ni = 0;
            for (int k = 0; k < ns && ni < 120; k++) {
                uint16_t ch = shown[k];
                if (ch == '/' || ch == '\\' || ch == ':') ch = ' ';
                ident[ni++] = ch;
            }
            while (ni && ident[ni - 1] == ' ') ni--;
            int s = 0; while (s < ni && ident[s] == ' ') s++;
            if (s) { memmove(ident, ident + s, (size_t)(ni - s) * 2); ni -= s; }
            ident[ni] = 0;
            if (!ni) { ident[0] = 'V'; ident[1] = 0; ni = 1; }
        } else continue;
        char id8[128]; es_utf8_from_u16(ident, ni, id8, sizeof id8);
        int dup = 0;
        for (int k = 0; k < nseen; k++) if (!strcmp(seen[k], id8)) dup = 1;
        if (dup) {
            for (int num = 2; num < 50 && dup; num++) {
                char trial[160]; snprintf(trial, sizeof trial, "%s %d", id8, num);
                dup = 0;
                for (int k = 0; k < nseen; k++) if (!strcmp(seen[k], trial)) dup = 1;
                if (!dup) {
                    size_t L = strlen(trial);
                    if (L >= sizeof id8) L = sizeof id8 - 1;
                    memcpy(id8, trial, L);
                    id8[L] = 0;
                }
            }
            ni = es_u16_from_utf8(id8, ident, 128);
        }
        if (nseen < 48) snprintf(seen[nseen++], 128, "%s", id8);
        EsRoot *o = &roots[nr++];
        memset(o, 0, sizeof *o);
        u16_copy(o->id, 128, &o->nid, ident, ni);
        u16_copy(o->name, 260, &o->nname, shown, ns);
        u16_copy(o->root, 1024, &o->nroot, root, nroot);
    }
    if (nr) { memcpy(es->roots, roots, (size_t)nr * sizeof(EsRoot)); es->nroots = nr; }
}

static uint64_t unix_time(uint64_t t) {
    if (t > 100000000000ULL) t = t / 10000000ULL - 11644473600ULL;
    return t;
}

static int parse_dir(int read_be, const uint8_t *msg, size_t len, EsDent **out, int *count) {
    *out = NULL; *count = 0;
    if (len < 3) return -1;
    Rd r = {msg + 1, msg + len, 0};
    uint16_t n = ru16(&r, read_be);
    EsDent *d = (EsDent *)calloc(n ? n : 1, sizeof *d);
    if (!d) return -1;
    int got = 0;
    for (uint16_t i = 0; i < n; i++) {
        const uint8_t *e = take(&r, 0x228);
        if (!e) break;
        Rd f = {e, e + 0x228, 0};
        uint32_t attr = ru32(&f, read_be);
        uint64_t ctime = ru64(&f, read_be); ru64(&f, read_be); uint64_t mtime = ru64(&f, read_be), size = ru64(&f, read_be);
        uint32_t nb = ru32(&f, read_be);
        if (nb > 512) nb = 512;
        nb &= ~1u;
        int nn = ru16str(&f, read_be, d[got].name, 256, nb);
        if (!nn || (nn == 1 && d[got].name[0] == '.') || (nn == 2 && d[got].name[0] == '.' && d[got].name[1] == '.')) continue;
        d[got].nname = nn;
        d[got].isdir = (attr & 0x10) != 0;
        d[got].size = size;
        d[got].mtime = unix_time(mtime);
        d[got].ctime = unix_time(ctime);
        got++;
    }
    *out = d; *count = got;
    return 0;
}

typedef struct { uint32_t fid; uint16_t path[1024]; int npath; } FileRef;
static int read_file_list(Rd *r, int be, uint16_t count, FileRef *out, int cap) {
    int n = 0;
    for (uint16_t i = 0; i < count && !r->bad; i++) {
        uint32_t fid = ru32(r, be);
        uint16_t len = ru16(r, be);
        uint16_t path[1024]; int np = ru16str(r, be, path, 1024, len);
        if (r->bad) return -1;
        if (n < cap) { out[n].fid = fid; u16_copy(out[n].path, 1024, &out[n].npath, path, np); n++; }
    }
    return r->bad ? -1 : n;
}

static void pump_downloads(Es *es) {
    while (es->njobs && (unsigned)es->tx_count < es->max_tx && !es->stop) {
        Job *j = &es->jobs[0];
        if (j->idx >= j->n) { reply_finish(es, j->session); free(j->files); memmove(j, j + 1, (size_t)(--es->njobs) * sizeof *j); continue; }
        DlFile *f = &j->files[j->idx];
        if (!j->fh) {
            uint64_t sz = 0;
            j->fh = es->hooks.fs.open_read ? es->hooks.fs.open_read(es->hooks.fs.user, f->path, f->npath, &sz) : NULL;
            if (!j->fh) { reply_error(es, 0xA9, j->session, 5, 1, f->fid); free(f->path); j->idx++; continue; }
            j->size = sz; j->sent = 0; j->block = 0;
            j->blocks = (uint32_t)(sz ? (sz + ES_FILE_BLOCK - 1) / ES_FILE_BLOCK : 1);
            char show[512]; es_utf8_from_u16(f->path, f->npath, show, sizeof show);
            es_log(es, "Sending %s (%llu bytes)", show, (unsigned long long)sz);
        }
        uint32_t n = (uint32_t)((j->size - j->sent) < ES_FILE_BLOCK ? (j->size - j->sent) : ES_FILE_BLOCK);
        uint8_t *raw = (uint8_t *)malloc(17u + n);
        if (!raw) return;
        raw[0] = 0xA3;
        b32raw(raw + 1, es->write_be, f->fid);
        b32raw(raw + 5, es->write_be, j->blocks);
        b32raw(raw + 9, es->write_be, j->block + 1);
        b32raw(raw + 13, es->write_be, n);
        if (n && es->hooks.fs.read_at(j->fh, raw + 17, n, j->sent) != 0) {
            free(raw); reply_error(es, 0xA9, j->session, 5, 1, f->fid);
            es->hooks.fs.close_read(j->fh); j->fh = NULL; free(f->path); j->idx++; continue;
        }
        queue_msg(es, raw, 17u + n, new_session(es));
        free(raw);
        j->sent += n;
        if (++j->block < j->blocks) continue;
        es->hooks.fs.close_read(j->fh); j->fh = NULL;
        free(f->path);
        if (++j->idx == j->n) { reply_finish(es, j->session); free(j->files); memmove(j, j + 1, (size_t)(--es->njobs) * sizeof *j); }
    }
}

static void upload_block(Es *es, Rd *r) {
    uint32_t fid = ru32(r, es->read_be), total = ru32(r, es->read_be), idx = ru32(r, es->read_be), n = ru32(r, es->read_be);
    const uint8_t *data = take(r, n);
    if (r->bad || es->up_cancel || !data) return;
    const uint16_t *path = NULL; int npath = 0;
    for (int i = 0; i < es->up_n; i++) if (es->up_files[i].fid == fid) { path = es->up_files[i].path; npath = es->up_files[i].npath; }
    if (!path) return;
    if (idx == 1) {
        if (es->up_fh && es->hooks.fs.close_write) es->hooks.fs.close_write(es->up_fh);
        es->up_fh = es->hooks.fs.open_write ? es->hooks.fs.open_write(es->hooks.fs.user, path, npath) : NULL;
        if (!es->up_fh) { reply_error(es, 0xA5, es->up_session, 13, 0, 0); return; }
        free(es->up_path);
        es->up_path = (uint16_t *)malloc((size_t)(npath + 1) * 2);
        memcpy(es->up_path, path, (size_t)npath * 2); es->up_path[npath] = 0; es->up_npath = npath;
        char show[512]; es_utf8_from_u16(path, npath, show, sizeof show);
        es_log(es, "Receiving %s", show);
    }
    if (!es->up_fh) return;
    uint64_t off = (uint64_t)(idx - 1) * ES_FILE_BLOCK;
    if (es->hooks.fs.write_at(es->up_fh, data, n, off) != 0) {
        reply_error(es, 0xA5, es->up_session, 28, 0, 0);
        es->hooks.fs.close_write(es->up_fh); es->up_fh = NULL; return;
    }
    if (idx == total) { es->hooks.fs.close_write(es->up_fh); es->up_fh = NULL; }
    (void)total;
}

static void dispatch(Es *es, const uint8_t *msg, size_t len, uint32_t pkt_session) {
    if (!len || !msg) return;
    Rd r = {msg + 1, msg + len, 0};
    switch (msg[0]) {
    case 0x01:
        if (len < 2) return;
        es->remote_os = msg[1]; es->read_be = es->remote_os >= 8;
        es_log(es, "%s connected (OS code %u).", es_peer_name(es->remote_os), es->remote_os);
        reply_result(es, 0x01, 0, 0, (uint32_t)es->our_os * 0x01010101u);
        reply_volumes(es);
        adjust_booking(es);
        apply_vols(es);
        break;
    case 0x04: {
        uint16_t n = ru16(&r, es->read_be);
        uint16_t path[4096]; int np = ru16str(&r, es->read_be, path, 4096, n);
        if (r.bad) return;
        reply_result(es, 0x04, 0, 0, 0);
        reply_dir(es, path, np, pkt_session);
        break;
    }
    case 0x06: case 0x08: {
        ru32(&r, es->read_be); uint16_t n = ru16(&r, es->read_be);
        uint16_t path[4096]; int np = ru16str(&r, es->read_be, path, 4096, n);
        if (r.bad) return;
        int ok = es->hooks.fs.trash && es->hooks.fs.trash(es->hooks.fs.user, path, np) == 0;
        reply_result(es, msg[0], ok ? 0 : 1, 0, 0);
        break;
    }
    case 0x07: {
        ru32(&r, es->read_be); uint16_t n = ru16(&r, es->read_be);
        uint16_t path[4096]; int np = ru16str(&r, es->read_be, path, 4096, n);
        if (r.bad) return;
        int isdir = 0; uint64_t sz = 0, mt = 0;
        int exists = es->hooks.fs.stat_path && es->hooks.fs.stat_path(es->hooks.fs.user, path, np, &isdir, &sz, &mt) == 0;
        int ok = !exists && es->hooks.fs.mkdir && es->hooks.fs.mkdir(es->hooks.fs.user, path, np) == 0;
        reply_result(es, 0x07, ok ? 0 : 1, ok ? 0 : 17, 0);
        break;
    }
    case 0x09: {
        ru32(&r, es->read_be); uint16_t l1 = ru16(&r, es->read_be), l2 = ru16(&r, es->read_be);
        uint16_t a[4096], b[4096]; int na = ru16str(&r, es->read_be, a, 4096, l1), nb = ru16str(&r, es->read_be, b, 4096, l2);
        if (r.bad) return;
        int ok = es->hooks.fs.rename && es->hooks.fs.rename(es->hooks.fs.user, a, na, b, nb) == 0;
        reply_result(es, 0x09, ok ? 0 : 1, 0, 0);
        break;
    }
    case 0x0C: upload_block(es, &r); break;
    case 0x10: {
        uint32_t s = ru32(&r, es->read_be); uint16_t c = ru16(&r, es->read_be);
        FileRef refs[64]; int n = read_file_list(&r, es->read_be, c, refs, 64);
        if (n < 0) return;
        Job job; memset(&job, 0, sizeof job); job.session = s;
        job.files = (DlFile *)calloc((size_t)(n > 0 ? n : 1), sizeof(DlFile));
        Buf zeros = {0}; int nz = 0;
        int keep = 0;
        for (int i = 0; i < n; i++) {
            int isdir = 0; uint64_t sz = 0, mt = 0;
            if (!es->hooks.fs.stat_path || es->hooks.fs.stat_path(es->hooks.fs.user, refs[i].path, refs[i].npath, &isdir, &sz, &mt) != 0) {
                reply_error(es, 0xA9, s, 2, 1, refs[i].fid);
                reply_result(es, 0x10, 1, 2, 0);
                free(job.files); free(zeros.b); return;
            }
            if (sz == 0) { buf_u32(&zeros, es->write_be, refs[i].fid); nz++; }
            else {
                job.files[keep].fid = refs[i].fid;
                job.files[keep].path = (uint16_t *)malloc((size_t)(refs[i].npath + 1) * 2);
                memcpy(job.files[keep].path, refs[i].path, (size_t)refs[i].npath * 2);
                job.files[keep].path[refs[i].npath] = 0;
                job.files[keep].npath = refs[i].npath;
                keep++;
            }
        }
        job.n = keep;
        reply_result(es, 0x10, 0, 0, 0);
        if (nz) {
            Buf m = {0}; buf_u8(&m, 0xA6); buf_u32(&m, es->write_be, s); buf_u16(&m, es->write_be, (uint16_t)nz);
            buf_add(&m, zeros.b, zeros.n); queue_buf(es, &m, new_session(es));
        }
        free(zeros.b);
        if (keep) {
            es->jobs = (Job *)realloc(es->jobs, (size_t)(es->njobs + 1) * sizeof(Job));
            es->jobs[es->njobs++] = job;
        } else { free(job.files); if (s) reply_finish(es, s); }
        break;
    }
    case 0x11: {
        uint32_t s = ru32(&r, es->read_be);
        for (int i = 0; i < es->njobs; ) {
            if (es->jobs[i].session != s) { i++; continue; }
            if (es->jobs[i].fh && es->hooks.fs.close_read) es->hooks.fs.close_read(es->jobs[i].fh);
            for (int f = 0; f < es->jobs[i].n; f++) free(es->jobs[i].files[f].path);
            free(es->jobs[i].files);
            memmove(&es->jobs[i], &es->jobs[i + 1], (size_t)(--es->njobs - i) * sizeof(Job));
        }
        break;
    }
    case 0x12: {
        uint32_t s = ru32(&r, es->read_be); uint16_t c = ru16(&r, es->read_be);
        FileRef refs[64]; int n = read_file_list(&r, es->read_be, c, refs, 64);
        if (n < 0) return;
        drop_up(es);
        es->up_session = s; es->up_cancel = 0;
        es->up_files = (UpFile *)calloc((size_t)(n > 0 ? n : 1), sizeof(UpFile));
        es->up_n = n;
        for (int i = 0; i < n; i++) {
            es->up_files[i].fid = refs[i].fid;
            es->up_files[i].path = (uint16_t *)malloc((size_t)(refs[i].npath + 1) * 2);
            memcpy(es->up_files[i].path, refs[i].path, (size_t)refs[i].npath * 2);
            es->up_files[i].npath = refs[i].npath;
        }
        break;
    }
    case 0x13: {
        uint32_t s = ru32(&r, es->read_be); uint64_t total = ru64(&r, es->read_be);
        ru16(&r, es->read_be); uint16_t c = ru16(&r, es->read_be);
        FileRef refs[64]; int n = read_file_list(&r, es->read_be, c, refs, 64);
        if (n < 0) return;
        Buf exist = {0}; uint32_t ne = 0;
        for (int i = 0; i < n; i++) {
            int isdir = 0; uint64_t sz = 0, mt = 0;
            if (es->hooks.fs.stat_path && es->hooks.fs.stat_path(es->hooks.fs.user, refs[i].path, refs[i].npath, &isdir, &sz, &mt) == 0) {
                buf_u32(&exist, es->write_be, refs[i].fid); ne++;
            }
        }
        uint16_t probe[1024]; int nprobe = n ? refs[0].npath : 0;
        if (n) u16_copy(probe, 1024, &nprobe, refs[0].path, refs[0].npath);
        uint64_t freeb = 0; int ro = 0;
        if (es->hooks.fs.space) es->hooks.fs.space(es->hooks.fs.user, probe, nprobe, &freeb, &ro);
        Buf m = {0};
        buf_u8(&m, 0xA8); buf_u8(&m, 0); buf_u8(&m, total < freeb); buf_u8(&m, 1); buf_u8(&m, ro ? 1 : 0);
        buf_u32(&m, es->write_be, s); buf_u32(&m, es->write_be, ne); buf_add(&m, exist.b, exist.n); free(exist.b);
        queue_buf(es, &m, new_session(es));
        break;
    }
    case 0x14:
        if (ru32(&r, es->read_be) != es->up_session || r.bad) return;
        es->up_cancel = 1;
        if (es->up_fh) {
            es->hooks.fs.close_write(es->up_fh); es->up_fh = NULL;
            if (es->up_path && es->hooks.fs.trash) es->hooks.fs.trash(es->hooks.fs.user, es->up_path, es->up_npath);
        }
        break;
    case 0x15: {
        ru32(&r, es->read_be); uint16_t c = ru16(&r, es->read_be);
        FileRef refs[64]; int n = read_file_list(&r, es->read_be, c, refs, 64);
        if (n < 0) return;
        for (int i = 0; i < n; i++) {
            void *fh = es->hooks.fs.open_write ? es->hooks.fs.open_write(es->hooks.fs.user, refs[i].path, refs[i].npath) : NULL;
            if (fh && es->hooks.fs.close_write) es->hooks.fs.close_write(fh);
        }
        break;
    }
    case 0x37: {
        uint32_t mode = ru32(&r, es->read_be);
        uint64_t ctime = ru64(&r, es->read_be), mtime = ru64(&r, es->read_be);
        ru64(&r, es->read_be);
        uint32_t nb = ru32(&r, es->read_be);
        uint16_t path[4096]; int np = ru16str(&r, es->read_be, path, 4096, nb);
        if (r.bad) return;
        if (es->hooks.fs.set_meta) es->hooks.fs.set_meta(es->hooks.fs.user, path, np, mode, unix_time(ctime), unix_time(mtime));
        break;
    }
    case 0xA1: {
        if (len < 11) return;
        uint8_t cmd = msg[1];
        if (cmd == 0x01) {
            if (msg[3] && msg[3] != 0xFF && msg[3] == msg[4] && msg[3] == msg[5] && msg[3] == msg[6]) {
                es->remote_os = msg[3]; es->read_be = es->remote_os >= 8;
            }
            if (msg[2] == 0 && !es->logged_in) {
                es->logged_in = 1; adjust_booking(es); apply_vols(es);
                es_log(es, "Logged in to the other computer (%s).", es_peer_name(es->remote_os));
            }
        }
        es->got[cmd] = 1; es->res[cmd] = msg[2];
        break;
    }
    case 0xA2:
        if (es->want_dir) {
            free(es->dir_msg);
            es->dir_msg = (uint8_t *)malloc(len);
            memcpy(es->dir_msg, msg, len); es->dir_len = len;
        }
        break;
    case 0xA3: {
        uint32_t fid = ru32(&r, es->read_be); ru32(&r, es->read_be); ru32(&r, es->read_be); uint32_t n = ru32(&r, es->read_be);
        const uint8_t *p = take(&r, n);
        if (r.bad || !es->dl_write || fid != es->dl_session || es->dl_failed) break;
        if (es->dl_write(es->dl_user, p, n, es->dl_off) != 0) es->dl_failed = 1;
        else es->dl_off += n;
        break;
    }
    case 0xA4:
        free(es->vol);
        es->vol = (uint8_t *)malloc(len);
        memcpy(es->vol, msg, len); es->vol_len = len;
        apply_vols(es);
        break;
    case 0xA5: if (ru32(&r, es->read_be) == es->ul_session && !r.bad) es->ul_failed = 1; break;
    case 0xA7: if (ru32(&r, es->read_be) == es->dl_session && !r.bad) es->dl_done = 1; break;
    case 0xA8:
        if (es->want_a8) {
            free(es->a8); es->a8 = (uint8_t *)malloc(len); memcpy(es->a8, msg, len); es->a8_len = len;
        }
        break;
    case 0xA9: if (ru32(&r, es->read_be) == es->dl_session && !r.bad) es->dl_failed = 1; break;
    default: break;
    }
}

static void incoming_packet(Es *es, const uint8_t *pkt) {
    uint32_t session = rd_le32(pkt + 4), idx = rd_le32(pkt + 8), total = rd_le32(pkt + 12), n = rd_le32(pkt + 16);
    if (n > ES_PKT_MAX || total == 0 || total > 4096) return;
    es->activity = es_now(es);
    if (total == 1) { dispatch(es, pkt + ES_PKT_HDR, n, session); return; }
    Rx *slot = NULL;
    for (int i = 0; i < 8; i++) if (es->rx[i].used && es->rx[i].session == session) slot = &es->rx[i];
    if (!slot || idx == 0) {
        for (int i = 0; i < 8; i++) if (!es->rx[i].used || es->rx[i].session == session || idx == 0) {
            if (es->rx[i].used && es->rx[i].session != session && idx != 0) continue;
            slot = &es->rx[i]; break;
        }
        if (!slot) slot = &es->rx[0];
        free(slot->buf); memset(slot, 0, sizeof *slot);
        slot->used = 1; slot->session = session; slot->total = total;
    }
    if (slot->len + n > slot->cap) {
        size_t c = slot->cap ? slot->cap * 2 : 65536;
        while (c < slot->len + n) c *= 2;
        slot->buf = (uint8_t *)realloc(slot->buf, c); slot->cap = c;
    }
    memcpy(slot->buf + slot->len, pkt + ES_PKT_HDR, n); slot->len += n;
    if (++slot->got == slot->total) {
        uint8_t *m = slot->buf; size_t len = slot->len; uint32_t s = slot->session;
        slot->buf = NULL; slot->used = 0;
        dispatch(es, m, len, s);
        free(m);
    }
}

static int transmit(Es *es, unsigned nsend) {
    int rc = 0;
    for (unsigned i = 0, retry = 0; i < nsend && es->tx_head && !es->stop; ) {
        rc = es->hooks.scsi(es->hooks.user, 0xD9, 0x2A, 0xFF, 0, 0, es->tx_head->b, ES_PKT_SIZE, 0);
        if (rc == 0) {
            Tx *n = es->tx_head->next; free(es->tx_head); es->tx_head = n;
            if (!es->tx_head) es->tx_tail = NULL;
            es->tx_count--; i++; retry = 0; es->activity = es_now(es); continue;
        }
        if ((rc == 0x87 || rc == 0x88 || rc == 0x89) && ++retry < 100) continue;
        break;
    }
    return rc;
}

static void remote_gone(Es *es) {
    if (es->logged_in) es_log(es, "The other computer closed EasySuite.");
    if (es->logged_in || es->login_sent) es->conn_gen++;
    es->logged_in = 0; es->login_sent = 0; es->nroots = 0;
    free(es->vol); es->vol = NULL; es->vol_len = 0;
    free_tx(es);
    drop_jobs(es);
    drop_up(es);
    es->dl_failed = 1; es->ul_failed = 1;
}

static void send_login(Es *es) {
    Buf b = {0};
    buf_u8(&b, 0x01); buf_u8(&b, (uint8_t)es->our_os); buf_u8(&b, 0); buf_u8(&b, 0);
    if (es->our_os >= 8) { buf_u8(&b, 6); buf_add(&b, "MACOSX", 6); }
    else { buf_u8(&b, 7); buf_add(&b, "WINDOWS", 7); }
    queue_buf(es, &b, new_session(es));
    es->login_sent = 1; es->login_ms = es_now(es);
}

int es_serve_once(Es *es) {
    es_lock(es);
    if (es->stop) { es_unlock(es); return 0; }
    if (!es->hooks.scsi || !es->scratch) { es_unlock(es); return -1; }
    pump_downloads(es);
    unsigned want = (unsigned)es->tx_count < es->booking ? (unsigned)es->tx_count : es->booking;
    if (es->cont_tx >= 11) { es->cont_tx = 0; want = 0; }
    uint8_t st[8] = {0};
    int rc = es->hooks.scsi(es->hooks.user, 0xD8, 0, 3, (uint8_t)(want >> 8), (uint8_t)want, st, sizeof st, 1);
    if (rc < 0) {
        int dead = ++es->failures >= 3;
        if (dead) remote_gone(es);
        es_wake(es); es_unlock(es);
        return dead ? -1 : 200;
    }
    es->failures = 0;
    int nap = 0;
    int present = st[0] >= 5 && st[0] <= 7;
    if (present && !es->logged_in && (!es->login_sent || es_now(es) - es->login_ms > 5000)) {
        if (!es->said_wait) { es_log(es, "Waiting for EasySuite on the other computer."); es->said_wait = 1; }
        send_login(es);
    }
    switch (st[0]) {
    case 0: case 1: remote_gone(es); nap = 50; break;
    case 2: case 3: break;
    case 5: {
        es->cont_tx = 0; nap = 0;
        for (unsigned n = ((unsigned)st[1] << 8) | st[2]; n && !es->stop; n--) {
            int r = es->hooks.scsi(es->hooks.user, 0xD9, 0x28, 0x64, 0, 0, es->scratch, ES_PKT_SIZE, 1);
            if (r) { nap = r == 1 ? 100 : (r == 0x83 || r == 0x84) ? 0 : 1; break; }
            incoming_packet(es, es->scratch);
        }
        break;
    }
    case 6: case 7: {
        if (st[0] == 7 && !want) { es->cont_tx = 0; nap = es->tx_count ? 0 : 300; break; }
        es->cont_tx++;
        int r = transmit(es, st[0] == 6 ? 1 : want);
        nap = (r == 0 || r == 0x85 || r == 0x86) ? 0 : r == 1 ? 100 : 5;
        break;
    }
    default: nap = 5; break;
    }
    es_wake(es);
    es_unlock(es);
    return nap;
}

static int wait_until(Es *es, int (*done)(Es *)) {
    uint32_t gen = es->conn_gen;
    es->activity = es_now(es);
    while (!done(es)) {
        if (es->conn_gen != gen || !es->logged_in || es->stop) return 0;
        if (es->hooks.now_ms && es_now(es) - es->activity > 30000) return 0;
        if (!es->hooks.wait) return 0;
        es->hooks.wait(es->hooks.user, 500);
    }
    return 1;
}

static void send_path_cmd(Es *es, uint8_t cmd, uint32_t sess, const uint16_t *a, int na, const uint16_t *b, int nb) {
    Buf m = {0};
    buf_u8(&m, cmd); buf_u32(&m, es->write_be, sess); buf_u16(&m, es->write_be, (uint16_t)(na * 2));
    if (b) buf_u16(&m, es->write_be, (uint16_t)(nb * 2));
    buf_utf16(&m, es->write_be, a, na);
    if (b) buf_utf16(&m, es->write_be, b, nb);
    queue_buf(es, &m, sess);
}
static void send_files(Es *es, uint8_t cmd, uint32_t sess, uint32_t fid, const uint16_t *path, int n, uint32_t pkt_session) {
    Buf m = {0};
    buf_u8(&m, cmd); buf_u32(&m, es->write_be, sess); buf_u16(&m, es->write_be, 1);
    buf_u32(&m, es->write_be, fid); buf_u16(&m, es->write_be, (uint16_t)(n * 2)); buf_utf16(&m, es->write_be, path, n);
    queue_buf(es, &m, pkt_session);
}

static Es *g_wait_es;
static uint8_t g_wait_cmd;
static int cmd_done(Es *es) { (void)es; return g_wait_es->got[g_wait_cmd]; }
static int list_done(Es *es) { return es->dir_msg != NULL || (es->got[4] && es->res[4] != 0); }
static int a8_done(Es *es) { return es->a8 != NULL; }
static int dl_accept_done(Es *es) { return es->got[0x10] || es->dl_failed; }
static int dl_finish_done(Es *es) { return es->dl_done || es->dl_failed; }
static int ul_room(Es *es) { return (unsigned)es->tx_count < es->max_tx || es->ul_failed; }
static int ul_sent(Es *es) { return es->tx_count == 0 || es->ul_failed; }

static int simple_op(Es *es, uint8_t cmd, const uint16_t *a, int na, const uint16_t *b, int nb) {
    if (es->hooks.op_lock) es->hooks.op_lock(es->hooks.user);
    es_lock(es);
    int rc = -1;
    if (es->logged_in) {
        uint32_t s = new_session(es);
        es->got[cmd] = 0;
        g_wait_es = es; g_wait_cmd = cmd;
        send_path_cmd(es, cmd, s, a, na, b, nb);
        if (wait_until(es, cmd_done)) rc = es->res[cmd] == 0 ? 0 : -1;
    }
    es_unlock(es);
    if (es->hooks.op_unlock) es->hooks.op_unlock(es->hooks.user);
    return rc;
}

static int list_held(Es *es, const uint16_t *path, int n, EsDent **out, int *count) {
    *out = NULL; *count = 0;
    if (!es->logged_in) return -1;
    es->got[4] = 0; free(es->dir_msg); es->dir_msg = NULL; es->want_dir = 1;
    Buf m = {0}; buf_u8(&m, 0x04); buf_u16(&m, es->write_be, (uint16_t)(n * 2)); buf_utf16(&m, es->write_be, path, n);
    queue_buf(es, &m, 0);
    int ok = wait_until(es, list_done);
    es->want_dir = 0;
    if (!ok || !es->dir_msg) return -1;
    int rc = parse_dir(es->read_be, es->dir_msg, es->dir_len, out, count);
    free(es->dir_msg); es->dir_msg = NULL;
    return rc;
}

int es_list(Es *es, const uint16_t *path, int n, EsDent **out, int *count) {
    if (es->hooks.op_lock) es->hooks.op_lock(es->hooks.user);
    es_lock(es);
    int rc = list_held(es, path, n, out, count);
    es_unlock(es);
    if (es->hooks.op_unlock) es->hooks.op_unlock(es->hooks.user);
    return rc;
}
int es_mkdir(Es *es, const uint16_t *path, int n) { return simple_op(es, 0x07, path, n, NULL, 0); }
int es_rename(Es *es, const uint16_t *from, int nf, const uint16_t *to, int nt) { return simple_op(es, 0x09, from, nf, to, nt); }

static int simple_held(Es *es, uint8_t cmd, const uint16_t *a, int na, const uint16_t *b, int nb);

static int delete_held(Es *es, const uint16_t *path, int n) {
    EsDent *d = NULL; int c = 0;
    uint16_t parent[1024]; int np = 0;
    es_parent(path, n, parent, &np);
    if (list_held(es, parent, np, &d, &c) != 0) { free(d); return -1; }
    int isdir = -1;
    uint16_t base[1024]; int nb = n;
    int cut = 0; uint16_t sep = path_sep(path, n);
    for (int i = 0; i < n; i++) if (path[i] == sep) cut = i + 1;
    if (sep == '\\' && cut < 3) cut = 0;
    if (cut >= n) { base[0] = 0; nb = 0; }
    else { nb = n - cut; memcpy(base, path + cut, (size_t)nb * 2); base[nb] = 0; }
    for (int i = 0; i < c; i++) {
        int same = es_u16_eq(d[i].name, d[i].nname, base, nb);
        if (!same && es_is_windows_path(path, n)) {
            same = 1;
            if (d[i].nname != nb) same = 0;
            for (int k = 0; same && k < nb; k++) {
                uint16_t x = d[i].name[k], y = base[k];
                if (x >= 'A' && x <= 'Z') x = (uint16_t)(x - 'A' + 'a');
                if (y >= 'A' && y <= 'Z') y = (uint16_t)(y - 'A' + 'a');
                if (x != y) same = 0;
            }
        }
        if (same) isdir = d[i].isdir;
    }
    free(d);
    if (isdir < 0) return -1;
    if (isdir) {
        EsDent *kids = NULL; int kc = 0;
        if (list_held(es, path, n, &kids, &kc) != 0) { free(kids); return -1; }
        for (int i = 0; i < kc; i++) {
            uint16_t child[1024]; int nc = 0;
            es_join(path, n, kids[i].name, kids[i].nname, child, &nc);
            if (delete_held(es, child, nc) != 0) { free(kids); return -1; }
        }
        free(kids);
        return simple_held(es, 0x06, path, n, NULL, 0);
    }
    return simple_held(es, 0x08, path, n, NULL, 0);
}

/* simple_held was a stub. Real version, lock already held. */
static int simple_held(Es *es, uint8_t cmd, const uint16_t *a, int na, const uint16_t *b, int nb) {
    if (!es->logged_in) return -1;
    uint32_t s = new_session(es);
    es->got[cmd] = 0;
    g_wait_es = es; g_wait_cmd = cmd;
    send_path_cmd(es, cmd, s, a, na, b, nb);
    if (!wait_until(es, cmd_done)) return -1;
    return es->res[cmd] == 0 ? 0 : -1;
}

int es_delete_tree(Es *es, const uint16_t *path, int n) {
    if (es->hooks.op_lock) es->hooks.op_lock(es->hooks.user);
    es_lock(es);
    int rc = delete_held(es, path, n);
    es_unlock(es);
    if (es->hooks.op_unlock) es->hooks.op_unlock(es->hooks.user);
    return rc;
}

int es_download(Es *es, const uint16_t *path, int n, EsWriteFn write, void *user) {
    if (es->hooks.op_lock) es->hooks.op_lock(es->hooks.user);
    es_lock(es);
    int rc = -1;
    if (es->logged_in) {
        uint32_t s = new_session(es);
        es->dl_write = write; es->dl_user = user; es->dl_session = s; es->dl_off = 0;
        es->dl_done = es->dl_failed = 0; es->got[0x10] = 0;
        send_files(es, 0x10, s, s, path, n, new_session(es));
        if (wait_until(es, dl_accept_done) && es->got[0x10] && es->res[0x10] == 0 && !es->dl_failed) {
            if (wait_until(es, dl_finish_done) && es->dl_done && !es->dl_failed) rc = 0;
        }
        if (rc != 0 && es->logged_in && !es->dl_done) {
            Buf m = {0}; buf_u8(&m, 0x11); buf_u32(&m, es->write_be, s); buf_u32(&m, es->write_be, s);
            queue_buf(es, &m, new_session(es));
        }
        es->dl_write = NULL; es->dl_session = 0;
    }
    es_unlock(es);
    if (es->hooks.op_unlock) es->hooks.op_unlock(es->hooks.user);
    return rc;
}

int es_upload(Es *es, const uint16_t *path, int n, uint64_t size, EsReadFn read, void *user) {
    if (es->hooks.op_lock) es->hooks.op_lock(es->hooks.user);
    es_lock(es);
    int rc = -1;
    if (es->logged_in) {
        uint32_t s = new_session(es);
        free(es->a8); es->a8 = NULL; es->want_a8 = 1;
        Buf m = {0};
        buf_u8(&m, 0x13); buf_u32(&m, es->write_be, s); buf_u64(&m, es->write_be, size);
        buf_u16(&m, es->write_be, 0); buf_u16(&m, es->write_be, 1);
        buf_u32(&m, es->write_be, s); buf_u16(&m, es->write_be, (uint16_t)(n * 2)); buf_utf16(&m, es->write_be, path, n);
        queue_buf(es, &m, new_session(es));
        int ok = wait_until(es, a8_done);
        es->want_a8 = 0;
        if (ok && es->a8 && es->a8_len >= 5 && !es->a8[1] && !es->a8[4] && es->a8[2]) {
            es->ul_session = s; es->ul_failed = 0;
            send_files(es, size ? 0x12 : 0x15, s, s, path, n, new_session(es));
            uint32_t blocks = size ? (uint32_t)((size + ES_FILE_BLOCK - 1) / ES_FILE_BLOCK) : 0;
            int failed = 0;
            for (uint32_t i = 0; i < blocks && !failed; i++) {
                if (!wait_until(es, ul_room) || es->ul_failed) { failed = 1; break; }
                uint32_t nb = (uint32_t)((size - (uint64_t)i * ES_FILE_BLOCK) < ES_FILE_BLOCK ? (size - (uint64_t)i * ES_FILE_BLOCK) : ES_FILE_BLOCK);
                uint8_t *raw = (uint8_t *)malloc(17u + nb);
                raw[0] = 0x0C;
                b32raw(raw + 1, es->write_be, s);
                b32raw(raw + 5, es->write_be, blocks);
                b32raw(raw + 9, es->write_be, i + 1);
                b32raw(raw + 13, es->write_be, nb);
                if (read(user, raw + 17, nb, (uint64_t)i * ES_FILE_BLOCK) != 0) { free(raw); failed = 1; break; }
                queue_msg(es, raw, 17u + nb, new_session(es));
                free(raw);
            }
            ok = !failed && !es->ul_failed && wait_until(es, ul_sent);
            if (ok && es->hooks.wait) es->hooks.wait(es->hooks.user, 1000);
            if (ok && !es->ul_failed) {
                rc = 0;
                if (es->remote_os >= 8) {
                    /* Tell a Mac or Linux peer the file's dates. Windows peers ignore 0x37. */
                    uint64_t now = 1700000000ull;
                    Buf t = {0};
                    buf_u8(&t, 0x37); buf_u32(&t, es->write_be, 0644);
                    buf_u64(&t, es->write_be, now); buf_u64(&t, es->write_be, now); buf_u64(&t, es->write_be, now);
                    buf_u32(&t, es->write_be, (uint32_t)(n * 2)); buf_utf16(&t, es->write_be, path, n);
                    queue_buf(es, &t, new_session(es));
                }
            }
            if (rc != 0 && es->logged_in) {
                Buf c = {0}; buf_u8(&c, 0x14); buf_u32(&c, es->write_be, s); queue_buf(es, &c, new_session(es));
            }
            es->ul_session = 0;
        }
    }
    es_unlock(es);
    if (es->hooks.op_unlock) es->hooks.op_unlock(es->hooks.user);
    return rc;
}

int es_logged_in(Es *es) { es_lock(es); int v = es->logged_in; es_unlock(es); return v; }
int es_remote_os(Es *es) { es_lock(es); int v = es->remote_os; es_unlock(es); return v; }
int es_remote_be(Es *es) { es_lock(es); int v = es->read_be; es_unlock(es); return v; }
int es_roots(Es *es, EsRoot *out, int cap) {
    es_lock(es);
    int n = es->nroots < cap ? es->nroots : cap;
    if (n > 0) memcpy(out, es->roots, (size_t)n * sizeof(EsRoot));
    es_unlock(es);
    return n;
}

#ifdef SELFTEST
static int g_fail;
#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL %s\n", msg); g_fail++; } } while (0)

static void test_move(Es *src, Es *dst) {
    while (src->tx_head) {
        Tx *t = src->tx_head; src->tx_head = t->next;
        if (!src->tx_head) src->tx_tail = NULL;
        src->tx_count--;
        incoming_packet(dst, t->b);
        free(t);
    }
}

typedef struct MF { char path[512]; int dir; uint8_t *data; size_t len; uint64_t mtime; struct MF *next; } MF;
typedef struct { MF *head; EsVol vols[8]; int nvols; } Mem;

static MF *mf_find(Mem *m, const char *path) {
    for (MF *n = m->head; n; n = n->next) if (!strcmp(n->path, path)) return n;
    return NULL;
}
static char *mf_utf(const uint16_t *p, int n) {
    char *s = (char *)malloc(n * 3 + 4);
    es_utf8_from_u16(p, n, s, n * 3 + 4);
    return s;
}
static int mf_child(const char *dir, const char *full, char *name, int cap) {
    size_t ld = strlen(dir), lf = strlen(full);
    if (lf <= ld || strncmp(full, dir, ld)) return 0;
    const char *rest = full + ld;
    char sep = (strchr(dir, '\\') || (ld >= 2 && dir[1] == ':')) ? '\\' : '/';
    if (dir[ld - 1] != sep) { if (*rest != sep) return 0; rest++; }
    if (!*rest || strchr(rest, sep)) return 0;
    snprintf(name, (size_t)cap, "%s", rest);
    return 1;
}
static int mf_volumes(void *user, EsVol **out, int *count) {
    Mem *m = user; *count = m->nvols;
    *out = (EsVol *)calloc((size_t)(m->nvols ? m->nvols : 1), sizeof(EsVol));
    memcpy(*out, m->vols, (size_t)m->nvols * sizeof(EsVol));
    return 0;
}
static int mf_list(void *user, const uint16_t *path, int n, EsDent **out, int *count) {
    Mem *m = user; char *dir = mf_utf(path, n);
    int cap = 8, c = 0; EsDent *d = (EsDent *)calloc((size_t)cap, sizeof *d);
    for (MF *node = m->head; node; node = node->next) {
        char name[256];
        if (!mf_child(dir, node->path, name, sizeof name)) continue;
        if (c == cap) { cap *= 2; d = (EsDent *)realloc(d, (size_t)cap * sizeof *d); }
        memset(&d[c], 0, sizeof d[c]);
        d[c].isdir = node->dir; d[c].size = node->len; d[c].mtime = node->mtime;
        d[c].nname = es_u16_from_utf8(name, d[c].name, 256);
        c++;
    }
    free(dir); *out = d; *count = c; return 0;
}
static int mf_stat(void *user, const uint16_t *path, int n, int *isdir, uint64_t *size, uint64_t *mtime) {
    char *s = mf_utf(path, n); MF *node = mf_find(user, s); free(s);
    if (!node) return -1;
    *isdir = node->dir; *size = node->len; *mtime = node->mtime; return 0;
}
static int mf_mkdir(void *user, const uint16_t *path, int n) {
    Mem *m = user; char *s = mf_utf(path, n);
    if (mf_find(m, s)) { free(s); return -1; }
    MF *node = (MF *)calloc(1, sizeof *node); snprintf(node->path, sizeof node->path, "%s", s); node->dir = 1;
    node->next = m->head; m->head = node; free(s); return 0;
}
static int mf_rename(void *user, const uint16_t *from, int nf, const uint16_t *to, int nt) {
    char *a = mf_utf(from, nf), *b = mf_utf(to, nt);
    MF *node = mf_find(user, a); free(a);
    if (!node || mf_find(user, b)) { free(b); return -1; }
    snprintf(node->path, sizeof node->path, "%s", b); free(b); return 0;
}
static int mf_trash(void *user, const uint16_t *path, int n) {
    Mem *m = user; char *s = mf_utf(path, n);
    MF **pp = &m->head;
    while (*pp && strcmp((*pp)->path, s)) pp = &(*pp)->next;
    free(s);
    if (!*pp) return -1;
    MF *dead = *pp; *pp = dead->next; free(dead->data); free(dead); return 0;
}
static int mf_space(void *user, const uint16_t *path, int n, uint64_t *free_bytes, int *readonly) {
    (void)user; (void)path; (void)n; *free_bytes = 1ull << 40; *readonly = 0; return 0;
}
typedef struct { Mem *m; MF *node; } MFh;
static void *mf_open_read(void *user, const uint16_t *path, int n, uint64_t *size) {
    char *s = mf_utf(path, n); MF *node = mf_find(user, s); free(s);
    if (!node || node->dir) return NULL;
    MFh *h = (MFh *)calloc(1, sizeof *h); h->m = user; h->node = node; *size = node->len; return h;
}
static int mf_read(void *fh, void *buf, uint32_t n, uint64_t off) {
    MFh *h = fh; if (off + n > h->node->len) return -1;
    memcpy(buf, h->node->data + off, n); return 0;
}
static void mf_close_read(void *fh) { free(fh); }
static void *mf_open_write(void *user, const uint16_t *path, int n) {
    Mem *m = user; char *s = mf_utf(path, n);
    MF *node = mf_find(m, s);
    if (!node) { node = (MF *)calloc(1, sizeof *node); snprintf(node->path, sizeof node->path, "%s", s); node->next = m->head; m->head = node; }
    free(node->data); node->data = NULL; node->len = 0; node->dir = 0;
    MFh *h = (MFh *)calloc(1, sizeof *h); h->m = m; h->node = node; free(s); return h;
}
static int mf_write(void *fh, const void *buf, uint32_t n, uint64_t off) {
    MFh *h = fh; size_t need = (size_t)off + n;
    if (need > h->node->len) {
        h->node->data = (uint8_t *)realloc(h->node->data, need ? need : 1);
        if (need > h->node->len) memset(h->node->data + h->node->len, 0, need - h->node->len);
        h->node->len = need;
    }
    memcpy(h->node->data + off, buf, n); return 0;
}
static void mf_close_write(void *fh) { free(fh); }
static int mf_meta(void *user, const uint16_t *path, int n, uint32_t mode, uint64_t ctime, uint64_t mtime) {
    (void)mode; (void)ctime; char *s = mf_utf(path, n); MF *node = mf_find(user, s); free(s);
    if (!node) return -1; node->mtime = mtime; return 0;
}
static EsFs mf_fs(Mem *m) {
    EsFs f; memset(&f, 0, sizeof f); f.user = m;
    f.volumes = mf_volumes; f.list_dir = mf_list; f.stat_path = mf_stat; f.mkdir = mf_mkdir; f.rename = mf_rename;
    f.trash = mf_trash; f.space = mf_space; f.open_read = mf_open_read; f.read_at = mf_read; f.close_read = mf_close_read;
    f.open_write = mf_open_write; f.write_at = mf_write; f.close_write = mf_close_write; f.set_meta = mf_meta;
    return f;
}
static void mf_add_vol(Mem *m, char letter, const char *name, const char *path) {
    EsVol *v = &m->vols[m->nvols++];
    memset(v, 0, sizeof *v); v->letter = (uint8_t)letter; v->type = 0x12;
    v->nname = es_u16_from_utf8(name, v->name, 260);
    v->npath = es_u16_from_utf8(path, v->path, 1024);
    MF *node = (MF *)calloc(1, sizeof *node); snprintf(node->path, sizeof node->path, "%s", path); node->dir = 1;
    node->next = m->head; m->head = node;
}
static void mf_add_file(Mem *m, const char *path, const void *data, size_t n) {
    MF *node = (MF *)calloc(1, sizeof *node); snprintf(node->path, sizeof node->path, "%s", path);
    node->data = (uint8_t *)malloc(n ? n : 1); memcpy(node->data, data, n); node->len = n; node->mtime = 1700000000;
    node->next = m->head; m->head = node;
}

static void exchange(Es *a, Es *b) {
    for (int guard = 0; guard < 10000; guard++) {
        int pending = a->tx_count || b->tx_count || a->njobs || b->njobs;
        pump_downloads(a); pump_downloads(b);
        int busy = a->tx_count || b->tx_count;
        test_move(a, b);
        test_move(b, a);
        if (!a->tx_count && !b->tx_count && !a->njobs && !b->njobs) break;
        if (!pending && !busy) break;
    }
}

static void login_pair(Es *a, Es *b) {
    send_login(a); send_login(b);
    exchange(a, b);
}

int main(void) {
    uint8_t login[16];
    EsHooks none; memset(&none, 0, sizeof none);
    Es *w = es_new(ES_OS_WINDOWS, 0, &none);
    Es *l = es_new(ES_OS_LINUX, 1, &none);
    send_login(w);
    CHECK(w->tx_head && w->tx_head->b[ES_PKT_HDR] == 0x01 && w->tx_head->b[ES_PKT_HDR + 1] == 5
          && w->tx_head->b[ES_PKT_HDR + 4] == 7 && !memcmp(w->tx_head->b + ES_PKT_HDR + 5, "WINDOWS", 7), "windows login");
    send_login(l);
    CHECK(l->tx_head->b[ES_PKT_HDR] == 0x01 && l->tx_head->b[ES_PKT_HDR + 1] == 0x14
          && l->tx_head->b[ES_PKT_HDR + 4] == 6 && !memcmp(l->tx_head->b + ES_PKT_HDR + 5, "MACOSX", 6), "linux login");
    (void)login;
    free_tx(w); free_tx(l);

    uint16_t croot[8], foo[8], slash[4], users[8];
    int ncr = es_u16_from_ascii("C:\\", croot, 8);
    int nf = es_u16_from_ascii("foo", foo, 8);
    uint16_t joined[32]; int nj = 0;
    es_join(croot, ncr, foo, nf, joined, &nj);
    CHECK(es_u16_from_ascii("C:\\foo", (uint16_t[16]){0}, 16) && nj == 6 && joined[0] == 'C' && joined[3] == 'f', "join win");
    uint16_t expect[16]; int ne = es_u16_from_ascii("C:\\foo", expect, 16);
    CHECK(es_u16_eq(joined, nj, expect, ne), "join C:\\foo");
    uint16_t par[32]; int np = 0;
    es_parent(joined, nj, par, &np);
    CHECK(es_u16_eq(par, np, croot, ncr), "parent of C:\\foo");
    int ns = es_u16_from_ascii("/", slash, 4);
    int nu = es_u16_from_ascii("Users", users, 8);
    es_join(slash, ns, users, nu, joined, &nj);
    uint16_t uexp[16]; int nue = es_u16_from_ascii("/Users", uexp, 16);
    CHECK(es_u16_eq(joined, nj, uexp, nue), "join /Users");
    es_join(joined, nj, foo, nf, par, &np);
    es_parent(par, np, joined, &nj);
    CHECK(es_u16_eq(joined, nj, uexp, nue), "parent /Users/foo");
    es_parent(uexp, nue, par, &np);
    CHECK(np == 1 && par[0] == '/', "parent /Users");

    uint8_t *big = (uint8_t *)malloc(150000);
    for (int i = 0; i < 150000; i++) big[i] = (uint8_t)(i * 17);
    queue_msg(w, big, 150000, 77);
    CHECK(w->tx_count == 3, "three packets");
    uint8_t *back = NULL; size_t blen = 0;
    while (w->tx_head) {
        Tx *t = w->tx_head; w->tx_head = t->next; w->tx_count--;
        uint32_t session = rd_le32(t->b + 4), idx = rd_le32(t->b + 8), total = rd_le32(t->b + 12), n = rd_le32(t->b + 16);
        CHECK(session == 77 && total == 3, "packet header");
        if (!back) back = (uint8_t *)malloc(150000);
        memcpy(back + idx * ES_PKT_MAX, t->b + ES_PKT_HDR, n);
        blen += n; free(t);
    }
    w->tx_tail = NULL;
    CHECK(blen == 150000 && !memcmp(back, big, 150000), "reassembly");
    free(back); free(big);

    EsDent ent; memset(&ent, 0, sizeof ent);
    ent.isdir = 1; ent.size = 7; ent.mtime = 1700000000; ent.nname = es_u16_from_ascii("Hi", ent.name, 256);
    Buf be = {0}, le = {0};
    w->write_be = 1; append_entry(w, &be, &ent);
    w->write_be = 0; append_entry(w, &le, &ent);
    CHECK(be.n == 0x228 && le.n == 0x228, "entry size");
    CHECK(be.b[0x1C + 7] == 7 && be.b[0x1C] == 0 && le.b[0x1C] == 7 && le.b[0x1C + 7] == 0, "size endian");
    uint8_t a2be[3 + 0x228], a2le[3 + 0x228];
    a2be[0] = a2le[0] = 0xA2; a2be[1] = 0; a2be[2] = 1; a2le[1] = 1; a2le[2] = 0;
    memcpy(a2be + 3, be.b, be.n); memcpy(a2le + 3, le.b, le.n);
    EsDent *got = NULL; int ng = 0;
    CHECK(parse_dir(1, a2be, sizeof a2be, &got, &ng) == 0 && ng == 1 && got[0].isdir && got[0].size == 7
          && got[0].name[0] == 'H' && got[0].name[1] == 'i', "BE directory entry");
    free(got);
    CHECK(parse_dir(0, a2le, sizeof a2le, &got, &ng) == 0 && ng == 1 && got[0].size == 7 && got[0].mtime == 1700000000, "LE directory entry");
    free(got); free(be.b); free(le.b);

    Mem winmem, linmem, macmem; memset(&winmem, 0, sizeof winmem); memset(&linmem, 0, sizeof linmem); memset(&macmem, 0, sizeof macmem);
    mf_add_vol(&winmem, 'C', "Windows", "C:\\");
    mf_add_file(&winmem, "C:\\a.txt", "pc", 2);
    mf_add_vol(&linmem, 'A', "Root", "/");
    mf_add_file(&linmem, "/notes.txt", "lin", 3);
    mf_add_vol(&macmem, 'A', "HD", "/Volumes/HD");
    mf_add_file(&macmem, "/Volumes/HD/mac.txt", "mac", 3);
    es_free(w); es_free(l);
    EsHooks hw = none, hl = none, hm = none;
    hw.fs = mf_fs(&winmem); hl.fs = mf_fs(&linmem); hm.fs = mf_fs(&macmem);
    Es *win = es_new(ES_OS_WINDOWS, 0, &hw);
    Es *lin = es_new(ES_OS_LINUX, 1, &hl);
    Es *mac = es_new(ES_OS_MAC, 1, &hm);
    login_pair(win, lin);
    CHECK(win->logged_in && lin->logged_in, "win-linux login");
    CHECK(win->read_be && !lin->read_be, "win-linux endian");
    CHECK(win->nroots == 1 && win->roots[0].root[0] == '/', "win sees linux root");
    CHECK(lin->nroots == 1 && lin->roots[0].root[0] == 'C' && lin->roots[0].root[2] == '\\', "linux sees C:\\");
    uint16_t lroot[8]; int nlr = es_u16_from_ascii("/", lroot, 8);
    win->want_dir = 1; free(win->dir_msg); win->dir_msg = NULL;
    {
        Buf m = {0}; buf_u8(&m, 0x04); buf_u16(&m, 0, (uint16_t)(nlr * 2)); buf_utf16(&m, 0, lroot, nlr);
        queue_buf(win, &m, 0);
    }
    exchange(win, lin);
    CHECK(win->dir_msg && parse_dir(win->read_be, win->dir_msg, win->dir_len, &got, &ng) == 0
          && ng == 1 && got[0].name[0] == 'n' && got[0].size == 3, "win lists linux");
    free(got); win->want_dir = 0;
    uint16_t wroot[8]; int nwr = es_u16_from_ascii("C:\\", wroot, 8);
    lin->want_dir = 1; free(lin->dir_msg); lin->dir_msg = NULL;
    {
        Buf m = {0}; buf_u8(&m, 0x04); buf_u16(&m, 1, (uint16_t)(nwr * 2)); buf_utf16(&m, 1, wroot, nwr);
        queue_buf(lin, &m, 0);
    }
    exchange(lin, win);
    CHECK(lin->dir_msg && parse_dir(lin->read_be, lin->dir_msg, lin->dir_len, &got, &ng) == 0
          && ng == 1 && got && got[0].size == 2 && got[0].name[0] == 'a', "linux lists windows");
    free(got); lin->want_dir = 0;

    login_pair(mac, win);
    CHECK(win->read_be == 1 && win->remote_os == ES_OS_MAC, "mac-pc os");
    CHECK(win->nroots == 1 && win->roots[0].nroot > 1, "pc sees mac volume");
    char macroot[128]; es_utf8_from_u16(win->roots[0].root, win->roots[0].nroot, macroot, sizeof macroot);
    CHECK(!strcmp(macroot, "/Volumes/HD"), "mac volume path");
    uint16_t mpath[64]; int nmp = es_u16_from_ascii("/Volumes/HD", mpath, 64);
    win->want_dir = 1; free(win->dir_msg); win->dir_msg = NULL;
    {
        Buf m = {0}; buf_u8(&m, 0x04); buf_u16(&m, 0, (uint16_t)(nmp * 2)); buf_utf16(&m, 0, mpath, nmp);
        queue_buf(win, &m, 0);
    }
    exchange(win, mac);
    CHECK(win->dir_msg && parse_dir(1, win->dir_msg, win->dir_len, &got, &ng) == 0
          && ng == 1 && got && got[0].size == 3, "pc lists mac");
    free(got); win->want_dir = 0;

    Es *lin2 = es_new(ES_OS_LINUX, 1, &hl);
    Es *lin3 = es_new(ES_OS_LINUX, 1, &hl);
    login_pair(lin2, lin3);
    CHECK(lin2->read_be && lin3->read_be && lin2->logged_in, "linux-linux");
    es_free(lin2); es_free(lin3);
    Es *w2 = es_new(ES_OS_WINDOWS, 0, &hw);
    Es *w3 = es_new(ES_OS_WINDOWS, 0, &hw);
    login_pair(w2, w3);
    CHECK(!w2->read_be && !w3->read_be && w2->roots[0].root[0] == 'C', "windows-windows");
    es_free(w2); es_free(w3);

    uint16_t up[64]; int nup = es_u16_from_ascii("/from-win.txt", up, 64);
    const char *payload = "hello-win";
    Buf put = {0};
    win->write_be = 0;
    buf_u8(&put, 0x12); buf_u32(&put, 0, 9); buf_u16(&put, 0, 1); buf_u32(&put, 0, 9);
    buf_u16(&put, 0, (uint16_t)(nup * 2)); buf_utf16(&put, 0, up, nup);
    dispatch(lin, put.b, put.n, 3); free(put.b);
    Buf blk = {0};
    buf_u8(&blk, 0x0C); buf_u32(&blk, 0, 9); buf_u32(&blk, 0, 1); buf_u32(&blk, 0, 1); buf_u32(&blk, 0, 9);
    buf_add(&blk, payload, 9);
    dispatch(lin, blk.b, blk.n, 4); free(blk.b);
    MF *saved = mf_find(&linmem, "/from-win.txt");
    CHECK(saved && saved->len == 9 && !memcmp(saved->data, payload, 9), "pc uploads to linux");

    uint16_t mapc[128]; int nmap = 0;
    EsRoot maproots[2]; memset(maproots, 0, sizeof maproots);
    maproots[0].nid = es_u16_from_ascii("C", maproots[0].id, 128);
    maproots[0].nroot = es_u16_from_ascii("C:\\", maproots[0].root, 1024);
    maproots[1].nid = es_u16_from_ascii("HD", maproots[1].id, 128);
    maproots[1].nroot = es_u16_from_ascii("/Volumes/HD", maproots[1].root, 1024);
    CHECK(es_map_path(maproots, 2, "/C/Users/a b", mapc, &nmap) == 0, "map win");
    uint16_t want[64]; int nw = es_u16_from_ascii("C:\\Users\\a b", want, 64);
    CHECK(es_u16_eq(mapc, nmap, want, nw), "mapped C path");
    CHECK(es_map_path(maproots, 2, "/HD/Users/a", mapc, &nmap) == 0, "map mac");
    nw = es_u16_from_ascii("/Volumes/HD/Users/a", want, 64);
    CHECK(es_u16_eq(mapc, nmap, want, nw), "mapped posix path");
    CHECK(es_map_path(maproots, 2, "/", mapc, &nmap) == 1, "map share");
    CHECK(es_map_path(maproots, 2, "/C/../x", mapc, &nmap) < 0, "map rejects dotdot");

    /* BE mkdir bytes match the Mac client's layout, aside from endianness. */
    uint16_t made[32]; int nm = es_u16_from_ascii("C:\\New", made, 32);
    Buf mk = {0};
    buf_u8(&mk, 0x07); buf_u32(&mk, 1, 0x11223344); buf_u16(&mk, 1, (uint16_t)(nm * 2)); buf_utf16(&mk, 1, made, nm);
    CHECK(mk.b[0] == 0x07 && mk.b[1] == 0x11 && mk.b[2] == 0x22 && mk.b[3] == 0x33 && mk.b[4] == 0x44, "BE mkdir session");
    CHECK(mk.b[5] == 0 && mk.b[6] == (uint8_t)(nm * 2) && mk.n == 7u + (size_t)nm * 2, "BE mkdir length");
    free(mk.b);

    es_free(win); es_free(lin); es_free(mac);
    if (g_fail) { fprintf(stderr, "selftest: %d failed\n", g_fail); return 1; }
    printf("selftest: OK\n");
    return 0;
}
#endif
