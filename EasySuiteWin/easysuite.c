/* EasySuite for Windows. Client and server on the OTi link cable.
   Build: make   (mingw-w64). The window is the file manager. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "proto.h"

#define WM_APP_STATUS (WM_APP + 1)
#define WM_APP_DONE   (WM_APP + 2)
#define ID_UP 1
#define ID_REFRESH 2
#define ID_MKDIR 3
#define ID_DELETE 4
#define ID_RENAME 5
#define ID_GET 6
#define ID_PUT 7

typedef struct {
    SCSI_PASS_THROUGH_DIRECT s;
    ULONG filler;
    UCHAR sense[32];
} SPTD;

typedef struct {
    int kind;
    wchar_t a[1024], b[1024], local[1024];
    int rc;
    EsDent *dents;
    int nd;
    int at_root;
} JobReq;

typedef struct {
    CRITICAL_SECTION mu, op;
    CONDITION_VARIABLE cv;
    HANDLE scsi, thread;
    wchar_t skip;
    HWND hwnd, list, status, pathlab;
    HFONT font;
    Es *es;
    volatile LONG stop;
    int busy;
    wchar_t cur[1024];
    wchar_t logpath[MAX_PATH];
    HIMAGELIST icons;
} Plat;

typedef struct Row {
    wchar_t name[260];
    wchar_t wire[1024];
    int dir;
    uint64_t size, mtime;
} Row;

static Plat g;
static Row *g_rows;
static int g_nrows;
static wchar_t g_ask[512];
static int g_ask_ok;

static int fwrite_wrap(void *user, const void *buf, uint32_t n, uint64_t off);
static int file_read(void *user, void *buf, uint32_t n, uint64_t off);

static void u16_to_w(const uint16_t *s, int n, wchar_t *w, int cap) {
    int i = 0;
    for (; i < n && i < cap - 1; i++) w[i] = (wchar_t)s[i];
    w[i] = 0;
}
static int w_to_u16(const wchar_t *w, uint16_t *s, int cap) {
    int n = 0;
    while (w[n] && n < cap - 1) { s[n] = (uint16_t)w[n]; n++; }
    s[n] = 0;
    return n;
}
static void to_long(const wchar_t *in, wchar_t *out, int cap) {
    if (in[0] && in[1] == L':' && !(in[0] == L'\\' && in[1] == L'\\' && in[2] == L'?' && in[3] == L'\\'))
        _snwprintf(out, (size_t)cap, L"\\\\?\\%s", in);
    else _snwprintf(out, (size_t)cap, L"%s", in);
}

static void plat_lock(void *u) { EnterCriticalSection(&((Plat *)u)->mu); }
static void plat_unlock(void *u) { LeaveCriticalSection(&((Plat *)u)->mu); }
static void plat_wait(void *u, int ms) { Plat *p = u; SleepConditionVariableCS(&p->cv, &p->mu, (DWORD)ms); }
static void plat_wake(void *u) { WakeAllConditionVariable(&((Plat *)u)->cv); }
static void plat_oplock(void *u) { EnterCriticalSection(&((Plat *)u)->op); }
static void plat_opunlock(void *u) { LeaveCriticalSection(&((Plat *)u)->op); }
static uint32_t plat_now(void) { return GetTickCount(); }

static void plat_log(void *u, const char *msg) {
    Plat *p = u;
    FILE *f = p->logpath[0] ? _wfopen(p->logpath, L"a") : NULL;
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
    if (!p->hwnd) return;
    int n = MultiByteToWideChar(CP_UTF8, 0, msg, -1, NULL, 0);
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return;
    MultiByteToWideChar(CP_UTF8, 0, msg, -1, w, n);
    PostMessageW(p->hwnd, WM_APP_STATUS, 0, (LPARAM)w);
}

static int sense_oti(const UCHAR *s) {
    uint8_t key = s[2] & 0x0f, asc = s[12], ascq = s[13];
    if (key == 9 && asc >= 0x80 && asc <= 0x89 && ascq == 0) return asc;
    unsigned k = ((unsigned)key << 16) | ((unsigned)asc << 8) | ascq;
    switch (k) {
    case 0x00000: return 4;
    case 0x23A00: case 0x63F0E: return 5;
    case 0x52000: case 0x72700: return 6;
    case 0x52400: return 7;
    case 0x62800: return 8;
    default: return 0xffff;
    }
}

static int scsi_raw(HANDLE h, const uint8_t cdb[16], void *buf, uint32_t len, int dir) {
    if (!h || h == INVALID_HANDLE_VALUE) return -1;
    SPTD sp; memset(&sp, 0, sizeof sp);
    sp.s.Length = sizeof sp.s;
    sp.s.CdbLength = 16;
    sp.s.SenseInfoLength = (UCHAR)sizeof sp.sense;
    sp.s.DataIn = (UCHAR)(dir == 1 ? SCSI_IOCTL_DATA_IN : dir == 0 ? SCSI_IOCTL_DATA_OUT : SCSI_IOCTL_DATA_UNSPECIFIED);
    sp.s.DataTransferLength = len;
    sp.s.TimeOutValue = dir == 1 ? 2 : 1;
    sp.s.DataBuffer = len ? buf : NULL;
    sp.s.SenseInfoOffset = (ULONG)offsetof(SPTD, sense);
    memcpy(sp.s.Cdb, cdb, 16);
    DWORD got = 0;
    if (!DeviceIoControl(h, IOCTL_SCSI_PASS_THROUGH_DIRECT, &sp, sizeof sp, &sp, sizeof sp, &got, NULL)) return -1;
    if (sp.s.ScsiStatus == 0) return 0;
    return sense_oti(sp.sense);
}

static int plat_scsi(void *u, uint8_t op, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, void *buf, uint32_t len, int dir) {
    uint8_t cdb[16] = {op, b1, b2, b3, b4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'O', 'T'};
    return scsi_raw(((Plat *)u)->scsi, cdb, buf, len, dir);
}

static int product_ok(const char *prod) {
    char b[160]; size_t n = 0;
    for (; prod[n] && n + 1 < sizeof b; n++) b[n] = (char)tolower((unsigned char)prod[n]);
    b[n] = 0;
    const char *names[] = {"easysuite", "easycopy-net", "easycopy", "easysync", "thunder bird", "crossbox",
                           "simpletransfer", "superlink", "sugoi cable", "ez share", NULL};
    for (int i = 0; names[i]; i++) if (strstr(b, names[i])) return 1;
    return 0;
}

static int query_product(HANDLE h, char *out, int cap) {
    STORAGE_PROPERTY_QUERY q; memset(&q, 0, sizeof q);
    q.PropertyId = StorageDeviceProperty; q.QueryType = PropertyStandardQuery;
    uint8_t buf[1024]; DWORD got = 0;
    if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, buf, sizeof buf, &got, NULL)) return 0;
    STORAGE_DEVICE_DESCRIPTOR *d = (STORAGE_DEVICE_DESCRIPTOR *)buf;
    if (!d->ProductIdOffset || d->ProductIdOffset >= got) return 0;
    _snprintf(out, (size_t)cap, "%s", (char *)buf + d->ProductIdOffset);
    return 1;
}

static void close_cable(void) {
    if (g.scsi && g.scsi != INVALID_HANDLE_VALUE) {
        DWORD dummy;
        DeviceIoControl(g.scsi, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &dummy, NULL);
        CloseHandle(g.scsi);
    }
    g.scsi = NULL;
}

static int try_open(const wchar_t *path, wchar_t letter) {
    HANDLE h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    char prod[128] = {0};
    if (!query_product(h, prod, sizeof prod) || !product_ok(prod)) { CloseHandle(h); return 0; }
    DWORD dummy;
    DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dummy, NULL);
    DeviceIoControl(h, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dummy, NULL);
    g.scsi = h; g.skip = letter;
    plat_log(&g, "Cable opened.");
    return 1;
}

static int open_cable(void) {
    wchar_t path[32];
    for (wchar_t L = L'A'; L <= L'Z'; L++) {
        wchar_t root[4] = {L, L':', L'\\', 0};
        UINT t = GetDriveTypeW(root);
        if (t != DRIVE_CDROM && t != DRIVE_UNKNOWN) continue;
        _snwprintf(path, 32, L"\\\\.\\%c:", L);
        if (try_open(path, L)) return 1;
    }
    for (int i = 0; i < 16; i++) {
        _snwprintf(path, 32, L"\\\\.\\CdRom%d", i);
        if (try_open(path, 0)) return 1;
    }
    return 0;
}

static int win_volumes(void *user, EsVol **out, int *count) {
    Plat *p = user; DWORD mask = GetLogicalDrives();
    EsVol *v = (EsVol *)calloc(26, sizeof *v); int n = 0;
    for (int i = 0; i < 26 && v; i++) {
        if (!(mask & (1u << i))) continue;
        wchar_t letter = (wchar_t)(L'A' + i);
        if (letter < L'C' || letter == p->skip) continue;
        wchar_t root[8]; _snwprintf(root, 8, L"%c:\\", letter);
        UINT t = GetDriveTypeW(root);
        if (t == DRIVE_NO_ROOT_DIR || t == DRIVE_UNKNOWN) continue;
        uint8_t type = 0x12;
        if (t == DRIVE_REMOTE) type = 0x13;
        else if (t == DRIVE_CDROM) type = 0x14;
        else if (t == DRIVE_REMOVABLE) type = 0x11;
        wchar_t label[64] = {0};
        if (!GetVolumeInformationW(root, label, 64, NULL, NULL, NULL, NULL, 0) || !label[0]) {
            label[0] = letter; label[1] = 0;
        }
        v[n].letter = (uint8_t)letter; v[n].type = type;
        v[n].nname = w_to_u16(label, v[n].name, 260);
        v[n].path[0] = (uint16_t)letter; v[n].path[1] = ':'; v[n].path[2] = '\\'; v[n].npath = 3;
        n++;
    }
    *out = v; *count = n; return 0;
}

static int win_list(void *user, const uint16_t *path, int n, EsDent **out, int *count) {
    (void)user; wchar_t w[1024], pat[1100], full[1100];
    u16_to_w(path, n, w, 1024); to_long(w, full, 1100);
    _snwprintf(pat, 1100, L"%s*", full);
    if (full[wcslen(full) - 1] != L'\\') _snwprintf(pat, 1100, L"%s\\*", full);
    WIN32_FIND_DATAW fd; HANDLE h = FindFirstFileW(pat, &fd);
    EsDent *d = NULL; int c = 0, cap = 0;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
            if (c == cap) { cap = cap ? cap * 2 : 32; d = (EsDent *)realloc(d, (size_t)cap * sizeof *d); }
            memset(&d[c], 0, sizeof d[c]);
            d[c].isdir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            d[c].size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            ULARGE_INTEGER u; u.LowPart = fd.ftLastWriteTime.dwLowDateTime; u.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            d[c].mtime = u.QuadPart > 116444736000000000ULL ? (u.QuadPart - 116444736000000000ULL) / 10000000ULL : 0;
            u.LowPart = fd.ftCreationTime.dwLowDateTime; u.HighPart = fd.ftCreationTime.dwHighDateTime;
            d[c].ctime = u.QuadPart > 116444736000000000ULL ? (u.QuadPart - 116444736000000000ULL) / 10000000ULL : 0;
            d[c].nname = w_to_u16(fd.cFileName, d[c].name, 256);
            c++;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    *out = d; *count = c; return h == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_NOT_FOUND ? -1 : 0;
}

static int win_stat(void *user, const uint16_t *path, int n, int *isdir, uint64_t *size, uint64_t *mtime) {
    (void)user; wchar_t w[1024], full[1100]; u16_to_w(path, n, w, 1024); to_long(w, full, 1100);
    WIN32_FILE_ATTRIBUTE_DATA a;
    if (!GetFileAttributesExW(full, GetFileExInfoStandard, &a)) return -1;
    *isdir = (a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    *size = ((uint64_t)a.nFileSizeHigh << 32) | a.nFileSizeLow;
    ULARGE_INTEGER u; u.LowPart = a.ftLastWriteTime.dwLowDateTime; u.HighPart = a.ftLastWriteTime.dwHighDateTime;
    *mtime = u.QuadPart > 116444736000000000ULL ? (u.QuadPart - 116444736000000000ULL) / 10000000ULL : 0;
    return 0;
}
static int win_mkdir(void *user, const uint16_t *path, int n) {
    (void)user; wchar_t w[1024], full[1100]; u16_to_w(path, n, w, 1024); to_long(w, full, 1100);
    return CreateDirectoryW(full, NULL) ? 0 : -1;
}
static int win_rename(void *user, const uint16_t *from, int nf, const uint16_t *to, int nt) {
    (void)user; wchar_t a[1024], b[1024], la[1100], lb[1100];
    u16_to_w(from, nf, a, 1024); u16_to_w(to, nt, b, 1024); to_long(a, la, 1100); to_long(b, lb, 1100);
    return MoveFileExW(la, lb, MOVEFILE_COPY_ALLOWED) ? 0 : -1;
}
static int win_trash(void *user, const uint16_t *path, int n) {
    (void)user; wchar_t w[1024]; u16_to_w(path, n, w, 1024);
    wchar_t buf[1200]; memset(buf, 0, sizeof buf); _snwprintf(buf, 1100, L"%s", w);
    SHFILEOPSTRUCTW op; memset(&op, 0, sizeof op);
    op.wFunc = FO_DELETE; op.pFrom = buf;
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    if (SHFileOperationW(&op) == 0 && !op.fAnyOperationsAborted) return 0;
    wchar_t full[1100]; to_long(w, full, 1100);
    DWORD attr = GetFileAttributesW(full);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) return RemoveDirectoryW(full) ? 0 : -1;
    return DeleteFileW(full) ? 0 : -1;
}
static int win_space(void *user, const uint16_t *path, int n, uint64_t *free_bytes, int *readonly) {
    (void)user; wchar_t w[1024]; u16_to_w(path, n, w, 1024);
    wchar_t probe[1024]; _snwprintf(probe, 1024, L"%s", w);
    DWORD attr = GetFileAttributesW(probe);
    while (attr == INVALID_FILE_ATTRIBUTES && wcslen(probe) > 3) {
        wchar_t *sl = wcsrchr(probe, L'\\'); if (!sl) break; *sl = 0; attr = GetFileAttributesW(probe);
    }
    ULARGE_INTEGER avail, total, totfree;
    if (!GetDiskFreeSpaceExW(probe[0] ? probe : L"C:\\", &avail, &total, &totfree)) { *free_bytes = 0; *readonly = 1; return -1; }
    *free_bytes = avail.QuadPart;
    *readonly = (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY)) ? 1 : 0;
    return 0;
}

typedef struct { HANDLE h; } WinFh;
static void *win_open_read(void *user, const uint16_t *path, int n, uint64_t *size) {
    (void)user; wchar_t w[1024], full[1100]; u16_to_w(path, n, w, 1024); to_long(w, full, 1100);
    HANDLE h = CreateFileW(full, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz; if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return NULL; }
    *size = (uint64_t)sz.QuadPart;
    WinFh *f = (WinFh *)calloc(1, sizeof *f); f->h = h; return f;
}
static int io_at(HANDLE h, void *buf, uint32_t n, uint64_t off, int wr) {
    OVERLAPPED o; memset(&o, 0, sizeof o);
    o.Offset = (DWORD)off; o.OffsetHigh = (DWORD)(off >> 32);
    DWORD got = 0;
    BOOL ok = wr ? WriteFile(h, buf, n, &got, &o) : ReadFile(h, buf, n, &got, &o);
    return ok && got == n ? 0 : -1;
}
static int win_read(void *fh, void *buf, uint32_t n, uint64_t off) { return io_at(((WinFh *)fh)->h, buf, n, off, 0); }
static void win_close_read(void *fh) { CloseHandle(((WinFh *)fh)->h); free(fh); }
static void *win_open_write(void *user, const uint16_t *path, int n) {
    (void)user; wchar_t w[1024], full[1100]; u16_to_w(path, n, w, 1024); to_long(w, full, 1100);
    HANDLE h = CreateFileW(full, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    WinFh *f = (WinFh *)calloc(1, sizeof *f); f->h = h; return f;
}
static int win_write(void *fh, const void *buf, uint32_t n, uint64_t off) { return io_at(((WinFh *)fh)->h, (void *)buf, n, off, 1); }
static void win_close_write(void *fh) { CloseHandle(((WinFh *)fh)->h); free(fh); }
static int win_meta(void *user, const uint16_t *path, int n, uint32_t mode, uint64_t ctime, uint64_t mtime) {
    (void)user; (void)mode; wchar_t w[1024], full[1100]; u16_to_w(path, n, w, 1024); to_long(w, full, 1100);
    HANDLE h = CreateFileW(full, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    ULARGE_INTEGER c, m;
    c.QuadPart = (ctime + 11644473600ULL) * 10000000ULL;
    m.QuadPart = (mtime + 11644473600ULL) * 10000000ULL;
    FILETIME fc, fm; fc.dwLowDateTime = c.LowPart; fc.dwHighDateTime = c.HighPart; fm.dwLowDateTime = m.LowPart; fm.dwHighDateTime = m.HighPart;
    int rc = SetFileTime(h, &fc, NULL, &fm) ? 0 : -1;
    CloseHandle(h); return rc;
}

static DWORD WINAPI cable_thread(void *arg) {
    (void)arg;
    while (!g.stop) {
        if (!g.scsi) {
            if (!open_cable()) { Sleep(2000); continue; }
            uint8_t ver[12] = {0}, bus[2] = {0};
            uint8_t cdb[16] = {0xF0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'O', 'T'};
            scsi_raw(g.scsi, cdb, ver, sizeof ver, 1);
            cdb[0] = 0xD8; cdb[2] = 2; scsi_raw(g.scsi, cdb, bus, sizeof bus, 1);
            cdb[1] = 1; cdb[2] = 5; cdb[4] = 0x7F; scsi_raw(g.scsi, cdb, NULL, 0, 2);
            char line[128];
            _snprintf(line, sizeof line, "Cable ready (firmware %.6s, USB %s).", (char *)ver + 6, bus[0] == 0x20 ? "2.0" : bus[0] == 0x11 ? "1.1" : "?");
            plat_log(&g, line);
            es_set_bus(g.es, bus[0], bus[1]);
        }
        int nap = es_serve_once(g.es);
        if (g.stop) break;
        if (nap < 0) { close_cable(); Sleep(500); continue; }
        if (nap > 0) Sleep((DWORD)nap);
    }
    close_cable();
    return 0;
}

static void format_size(uint64_t n, wchar_t *out, int cap) {
    if (n < 1024) _snwprintf(out, (size_t)cap, L"%llu bytes", (unsigned long long)n);
    else if (n < 1024 * 1024) _snwprintf(out, (size_t)cap, L"%.1f KB", n / 1024.0);
    else if (n < 1024ull * 1024 * 1024) _snwprintf(out, (size_t)cap, L"%.1f MB", n / (1024.0 * 1024));
    else _snwprintf(out, (size_t)cap, L"%.2f GB", n / (1024.0 * 1024 * 1024));
}
static void format_time(uint64_t unix_s, wchar_t *out, int cap) {
    if (!unix_s) { out[0] = 0; return; }
    ULARGE_INTEGER u; u.QuadPart = (unix_s + 11644473600ULL) * 10000000ULL;
    FILETIME ft, lt; SYSTEMTIME st;
    ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart;
    FileTimeToLocalFileTime(&ft, &lt); FileTimeToSystemTime(&lt, &st);
    _snwprintf(out, (size_t)cap, L"%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
}

static void fill_list(void) {
    ListView_DeleteAllItems(g.list);
    for (int i = 0; i < g_nrows; i++) {
        wchar_t size[64], when[64];
        if (g_rows[i].dir) _snwprintf(size, 64, L"");
        else format_size(g_rows[i].size, size, 64);
        format_time(g_rows[i].mtime, when, 64);
        SHFILEINFOW sfi; memset(&sfi, 0, sizeof sfi);
        SHGetFileInfoW(g_rows[i].dir ? L"dir" : g_rows[i].name,
                       g_rows[i].dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL,
                       &sfi, sizeof sfi, SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
        LVITEMW it; memset(&it, 0, sizeof it);
        it.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM; it.iItem = i; it.pszText = g_rows[i].name; it.iImage = sfi.iIcon; it.lParam = i;
        ListView_InsertItem(g.list, &it);
        ListView_SetItemText(g.list, i, 1, size);
        ListView_SetItemText(g.list, i, 2, when);
        ListView_SetItemText(g.list, i, 3, g_rows[i].dir ? L"Folder" : L"File");
    }
    wchar_t cap[1200];
    if (!g.cur[0]) _snwprintf(cap, 1200, L"EasySuite");
    else _snwprintf(cap, 1200, L"%s", g.cur);
    SetWindowTextW(g.pathlab, cap);
}

static int path_is_root(const wchar_t *p) {
    EsRoot *r = (EsRoot *)calloc(48, sizeof *r);
    int n = g.es ? es_roots(g.es, r, 48) : 0, yes = 0;
    for (int i = 0; i < n; i++) {
        wchar_t w[1024]; u16_to_w(r[i].root, r[i].nroot, w, 1024);
        if (!wcscmp(w, p)) yes = 1;
    }
    free(r); return yes;
}

static void show_roots(void) {
    EsRoot *r = (EsRoot *)calloc(48, sizeof *r);
    int n = g.es ? es_roots(g.es, r, 48) : 0;
    free(g_rows); g_rows = (void *)calloc((size_t)(n ? n : 1), sizeof *g_rows); g_nrows = n;
    for (int i = 0; i < n; i++) {
        u16_to_w(r[i].name, r[i].nname, g_rows[i].name, 260);
        u16_to_w(r[i].root, r[i].nroot, g_rows[i].wire, 1024);
        g_rows[i].dir = 1;
    }
    free(r);
    g.cur[0] = 0;
    fill_list();
}

static DWORD WINAPI job_thread(void *arg) {
    JobReq *j = arg;
    uint16_t a[1024], b[1024]; int na = 0, nb = 0;
    if (j->a[0]) na = w_to_u16(j->a, a, 1024);
    if (j->b[0]) nb = w_to_u16(j->b, b, 1024);
    j->rc = -1;
    if (j->kind == 0) j->rc = es_list(g.es, a, na, &j->dents, &j->nd);
    else if (j->kind == 1) j->rc = es_mkdir(g.es, a, na);
    else if (j->kind == 2) j->rc = es_delete_tree(g.es, a, na);
    else if (j->kind == 3) j->rc = es_rename(g.es, a, na, b, nb);
    else if (j->kind == 4) {
        FILE *fp = _wfopen(j->local, L"wb");
        if (!fp) j->rc = -1;
        else {
            j->rc = es_download(g.es, a, na, (EsWriteFn)fwrite_wrap, fp);
            fclose(fp);
            if (j->rc != 0) _wremove(j->local);
        }
    } else if (j->kind == 5) {
        FILE *fp = _wfopen(j->local, L"rb");
        if (!fp) j->rc = -1;
        else {
            _fseeki64(fp, 0, SEEK_END); uint64_t sz = (uint64_t)_ftelli64(fp); _fseeki64(fp, 0, SEEK_SET);
            j->rc = es_upload(g.es, a, na, sz, file_read, fp);
            fclose(fp);
        }
    }
    PostMessageW(g.hwnd, WM_APP_DONE, 0, (LPARAM)j);
    return 0;
}

static int fwrite_wrap(void *user, const void *buf, uint32_t n, uint64_t off) {
    FILE *fp = user;
    if (_fseeki64(fp, (long long)off, SEEK_SET) != 0) return -1;
    return fwrite(buf, 1, n, fp) == n ? 0 : -1;
}
static int file_read(void *user, void *buf, uint32_t n, uint64_t off) {
    FILE *fp = user;
    if (_fseeki64(fp, (long long)off, SEEK_SET) != 0) return -1;
    return fread(buf, 1, n, fp) == n ? 0 : -1;
}

static void start_job(JobReq *j) {
    if (g.busy || !g.es || !es_logged_in(g.es)) { free(j); return; }
    g.busy = 1;
    SetWindowTextW(g.status, L"Working…");
    HANDLE t = CreateThread(NULL, 0, job_thread, j, 0, NULL);
    if (t) CloseHandle(t); else { g.busy = 0; free(j); }
}

static void start_list(const wchar_t *wire) {
    JobReq *j = (JobReq *)calloc(1, sizeof *j);
    j->kind = 0; _snwprintf(j->a, 1024, L"%s", wire);
    start_job(j);
}

static int selected_row(void) {
    int i = ListView_GetNextItem(g.list, -1, LVNI_SELECTED);
    return i;
}

static void enter_row(int i) {
    if (i < 0 || i >= g_nrows) return;
    if (!g_rows[i].dir) return;
    _snwprintf(g.cur, 1024, L"%s", g_rows[i].wire);
    start_list(g.cur);
}

static void do_up(void) {
    if (g.busy) return;
    if (!g.cur[0]) return;
    if (path_is_root(g.cur)) { show_roots(); return; }
    uint16_t cur[1024], par[1024]; int nc = w_to_u16(g.cur, cur, 1024), np = 0;
    es_parent(cur, nc, par, &np);
    u16_to_w(par, np, g.cur, 1024);
    start_list(g.cur);
}

static BOOL ask_text(HWND owner, const wchar_t *title, wchar_t *buf, int cap);

static void do_mkdir(void) {
    if (g.busy || !g.cur[0]) return;
    wchar_t name[260] = L"";
    if (!ask_text(g.hwnd, L"New folder", name, 260)) return;
    uint16_t cur[1024], nm[260], joined[1024];
    int nc = w_to_u16(g.cur, cur, 1024), nn = w_to_u16(name, nm, 260), nj = 0;
    es_join(cur, nc, nm, nn, joined, &nj);
    JobReq *j = (JobReq *)calloc(1, sizeof *j); j->kind = 1;
    u16_to_w(joined, nj, j->a, 1024);
    start_job(j);
}
static void do_delete(void) {
    int i = selected_row(); if (i < 0 || g.busy || !g.cur[0]) return;
    wchar_t msg[1200]; _snwprintf(msg, 1200, L"Delete \"%s\"?", g_rows[i].name);
    if (MessageBoxW(g.hwnd, msg, L"EasySuite", MB_OKCANCEL | MB_ICONWARNING) != IDOK) return;
    JobReq *j = (JobReq *)calloc(1, sizeof *j); j->kind = 2; _snwprintf(j->a, 1024, L"%s", g_rows[i].wire);
    start_job(j);
}
static void do_rename(void) {
    int i = selected_row(); if (i < 0 || g.busy || !g.cur[0]) return;
    wchar_t name[260]; _snwprintf(name, 260, L"%s", g_rows[i].name);
    if (!ask_text(g.hwnd, L"Rename", name, 260)) return;
    uint16_t cur[1024], nm[260], joined[1024];
    int nc = w_to_u16(g.cur, cur, 1024), nn = w_to_u16(name, nm, 260), nj = 0;
    es_join(cur, nc, nm, nn, joined, &nj);
    JobReq *j = (JobReq *)calloc(1, sizeof *j); j->kind = 3;
    _snwprintf(j->a, 1024, L"%s", g_rows[i].wire);
    u16_to_w(joined, nj, j->b, 1024);
    start_job(j);
}
static void do_get(void) {
    int i = selected_row(); if (i < 0 || g.busy || g_rows[i].dir) return;
    wchar_t file[1024]; _snwprintf(file, 1024, L"%s", g_rows[i].name);
    OPENFILENAMEW ofn; memset(&ofn, 0, sizeof ofn);
    ofn.lStructSize = sizeof ofn; ofn.hwndOwner = g.hwnd; ofn.lpstrFile = file; ofn.nMaxFile = 1024;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST; ofn.lpstrTitle = L"Download";
    if (!GetSaveFileNameW(&ofn)) return;
    JobReq *j = (JobReq *)calloc(1, sizeof *j); j->kind = 4;
    _snwprintf(j->a, 1024, L"%s", g_rows[i].wire); _snwprintf(j->local, 1024, L"%s", file);
    start_job(j);
}
static void do_put_path(const wchar_t *local) {
    if (g.busy || !g.cur[0]) return;
    const wchar_t *base = wcsrchr(local, L'\\'); base = base ? base + 1 : local;
    uint16_t cur[1024], nm[260], joined[1024];
    int nc = w_to_u16(g.cur, cur, 1024), nn = w_to_u16(base, nm, 260), nj = 0;
    es_join(cur, nc, nm, nn, joined, &nj);
    JobReq *j = (JobReq *)calloc(1, sizeof *j); j->kind = 5;
    u16_to_w(joined, nj, j->a, 1024); _snwprintf(j->local, 1024, L"%s", local);
    start_job(j);
}
static void do_put(void) {
    wchar_t file[1024] = {0};
    OPENFILENAMEW ofn; memset(&ofn, 0, sizeof ofn);
    ofn.lStructSize = sizeof ofn; ofn.hwndOwner = g.hwnd; ofn.lpstrFile = file; ofn.nMaxFile = 1024;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST; ofn.lpstrTitle = L"Upload";
    if (!GetOpenFileNameW(&ofn)) return;
    do_put_path(file);
}

static LRESULT CALLBACK ask_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_COMMAND && LOWORD(w) == IDOK) { g_ask_ok = 1; GetDlgItemTextW(h, 100, g_ask, 512); DestroyWindow(h); return 0; }
    if ((m == WM_COMMAND && LOWORD(w) == IDCANCEL) || m == WM_CLOSE) { DestroyWindow(h); return 0; }
    if (m == WM_CREATE) {
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_ask, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 12, 14, 360, 24, h, (HMENU)100, NULL, NULL);
        CreateWindowW(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 200, 50, 80, 26, h, (HMENU)IDOK, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE, 290, 50, 80, 26, h, (HMENU)IDCANCEL, NULL, NULL);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
static BOOL ask_text(HWND owner, const wchar_t *title, wchar_t *buf, int cap) {
    _snwprintf(g_ask, 512, L"%s", buf); g_ask_ok = 0;
    static int reg = 0;
    if (!reg) {
        WNDCLASSW wc; memset(&wc, 0, sizeof wc); wc.lpfnWndProc = ask_proc; wc.hInstance = GetModuleHandleW(NULL);
        wc.lpszClassName = L"EasySuiteAsk"; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        RegisterClassW(&wc); reg = 1;
    }
    HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME, L"EasySuiteAsk", title, WS_CAPTION | WS_SYSMENU,
                             CW_USEDEFAULT, CW_USEDEFAULT, 400, 130, owner, NULL, GetModuleHandleW(NULL), NULL);
    EnableWindow(owner, FALSE); ShowWindow(h, SW_SHOW);
    MSG msg;
    while (IsWindow(h) && GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(h, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    }
    EnableWindow(owner, TRUE); SetForegroundWindow(owner);
    if (!g_ask_ok || !g_ask[0]) return FALSE;
    _snwprintf(buf, (size_t)cap, L"%s", g_ask);
    return TRUE;
}

static void on_done(JobReq *j) {
    g.busy = 0;
    if (j->kind == 0 && j->rc == 0) {
        free(g_rows); g_rows = (void *)calloc((size_t)(j->nd ? j->nd : 1), sizeof *g_rows); g_nrows = j->nd;
        for (int i = 0; i < j->nd; i++) {
            u16_to_w(j->dents[i].name, j->dents[i].nname, g_rows[i].name, 260);
            uint16_t cur[1024], joined[1024]; int nc = w_to_u16(j->a, cur, 1024), nj = 0;
            es_join(cur, nc, j->dents[i].name, j->dents[i].nname, joined, &nj);
            u16_to_w(joined, nj, g_rows[i].wire, 1024);
            g_rows[i].dir = j->dents[i].isdir; g_rows[i].size = j->dents[i].size; g_rows[i].mtime = j->dents[i].mtime;
        }
        _snwprintf(g.cur, 1024, L"%s", j->a);
        fill_list();
        SetWindowTextW(g.status, L"Ready.");
    } else if (j->kind == 0) {
        SetWindowTextW(g.status, L"Couldn't open that folder.");
    } else if (j->rc == 0 && g.cur[0]) {
        SetWindowTextW(g.status, L"Done.");
        start_list(g.cur);
    } else if (j->rc == 0) {
        SetWindowTextW(g.status, L"Done."); show_roots();
    } else SetWindowTextW(g.status, L"That didn't work.");
    free(j->dents); free(j);
}

static void layout(int w, int h) {
    int y = 8, x = 8;
    HWND child = GetWindow(g.hwnd, GW_CHILD);
    (void)child;
    const int ids[] = {ID_UP, ID_REFRESH, ID_MKDIR, ID_DELETE, ID_RENAME, ID_GET, ID_PUT};
    for (int i = 0; i < 7; i++) {
        HWND b = GetDlgItem(g.hwnd, ids[i]);
        MoveWindow(b, x, y, i == 2 || i == 4 ? 96 : 84, 28, TRUE);
        x += (i == 2 || i == 4 ? 96 : 84) + 6;
    }
    MoveWindow(g.pathlab, 8, 42, w - 16, 22, TRUE);
    MoveWindow(g.list, 0, 68, w, h - 68 - 26, TRUE);
    MoveWindow(g.status, 0, h - 24, w, 24, TRUE);
}

static LRESULT CALLBACK wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_SIZE: layout(LOWORD(l), HIWORD(l)); return 0;
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case ID_UP: do_up(); break;
        case ID_REFRESH: if (!g.cur[0]) show_roots(); else start_list(g.cur); break;
        case ID_MKDIR: do_mkdir(); break;
        case ID_DELETE: do_delete(); break;
        case ID_RENAME: do_rename(); break;
        case ID_GET: do_get(); break;
        case ID_PUT: do_put(); break;
        }
        return 0;
    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR *)l;
        if (nm->idFrom == 50 && nm->code == NM_DBLCLK) { enter_row(selected_row()); if (selected_row() >= 0 && !g_rows[selected_row()].dir) do_get(); }
        if (nm->idFrom == 50 && nm->code == LVN_KEYDOWN) {
            NMLVKEYDOWN *k = (NMLVKEYDOWN *)l;
            if (k->wVKey == VK_BACK) do_up();
            if (k->wVKey == VK_DELETE) do_delete();
            if (k->wVKey == VK_F5) { if (!g.cur[0]) show_roots(); else start_list(g.cur); }
        }
        return 0;
    }
    case WM_DROPFILES: {
        HDROP drop = (HDROP)w; wchar_t file[1024];
        UINT n = DragQueryFileW(drop, 0xFFFFFFFF, NULL, 0);
        for (UINT i = 0; i < n; i++) { DragQueryFileW(drop, i, file, 1024); do_put_path(file); }
        DragFinish(drop); return 0;
    }
    case WM_TIMER: {
        int in = g.es && es_logged_in(g.es);
        static int was = -1;
        if (in != was) {
            was = in;
            if (!in) { g.cur[0] = 0; free(g_rows); g_rows = NULL; g_nrows = 0; fill_list(); SetWindowTextW(g.status, L"Waiting for the other computer…"); }
            else { show_roots(); SetWindowTextW(g.status, L"Connected."); }
        }
        return 0;
    }
    case WM_APP_STATUS: SetWindowTextW(g.status, (wchar_t *)l); free((void *)l); return 0;
    case WM_APP_DONE: on_done((JobReq *)l); return 0;
    case WM_DESTROY: g.stop = 1; es_request_stop(g.es); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    (void)prev; (void)cmd;
    INITCOMMONCONTROLSEX icc = {sizeof icc, ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    GetTempPathW(MAX_PATH, g.logpath);
    wcsncat(g.logpath, L"easysuite.log", MAX_PATH - wcslen(g.logpath) - 1);
    InitializeCriticalSection(&g.mu); InitializeCriticalSection(&g.op); InitializeConditionVariable(&g.cv);
    EsHooks hooks; memset(&hooks, 0, sizeof hooks);
    hooks.user = &g; hooks.lock = plat_lock; hooks.unlock = plat_unlock; hooks.wait = plat_wait; hooks.wake = plat_wake;
    hooks.op_lock = plat_oplock; hooks.op_unlock = plat_opunlock; hooks.now_ms = plat_now; hooks.log = plat_log; hooks.scsi = plat_scsi;
    hooks.fs.user = &g; hooks.fs.volumes = win_volumes; hooks.fs.list_dir = win_list; hooks.fs.stat_path = win_stat;
    hooks.fs.mkdir = win_mkdir; hooks.fs.rename = win_rename; hooks.fs.trash = win_trash; hooks.fs.space = win_space;
    hooks.fs.open_read = win_open_read; hooks.fs.read_at = win_read; hooks.fs.close_read = win_close_read;
    hooks.fs.open_write = win_open_write; hooks.fs.write_at = win_write; hooks.fs.close_write = win_close_write; hooks.fs.set_meta = win_meta;
    g.es = es_new(ES_OS_WINDOWS, 0, &hooks);

    WNDCLASSW wc; memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = wnd_proc; wc.hInstance = inst; wc.lpszClassName = L"EasySuite";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);
    g.font = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    g.hwnd = CreateWindowExW(0, L"EasySuite", L"EasySuite", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 980, 640, NULL, NULL, inst, NULL);
    const wchar_t *labels[] = {L"Up", L"Refresh", L"New folder", L"Delete", L"Rename", L"Download", L"Upload"};
    const int ids[] = {ID_UP, ID_REFRESH, ID_MKDIR, ID_DELETE, ID_RENAME, ID_GET, ID_PUT};
    for (int i = 0; i < 7; i++) {
        HWND b = CreateWindowW(L"BUTTON", labels[i], WS_CHILD | WS_VISIBLE, 0, 0, 80, 28, g.hwnd, (HMENU)(INT_PTR)ids[i], inst, NULL);
        SendMessageW(b, WM_SETFONT, (WPARAM)g.font, 1);
    }
    g.pathlab = CreateWindowW(L"STATIC", L"EasySuite", WS_CHILD | WS_VISIBLE, 0, 0, 100, 20, g.hwnd, NULL, inst, NULL);
    SendMessageW(g.pathlab, WM_SETFONT, (WPARAM)g.font, 1);
    g.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                             0, 0, 100, 100, g.hwnd, (HMENU)50, inst, NULL);
    ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    SendMessageW(g.list, WM_SETFONT, (WPARAM)g.font, 1);
    const wchar_t *cols[] = {L"Name", L"Size", L"Modified", L"Kind"};
    int widths[] = {360, 110, 160, 90};
    for (int i = 0; i < 4; i++) {
        LVCOLUMNW c; memset(&c, 0, sizeof c); c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        c.pszText = (wchar_t *)cols[i]; c.cx = widths[i]; c.fmt = i == 1 ? LVCFMT_RIGHT : LVCFMT_LEFT;
        ListView_InsertColumn(g.list, i, &c);
    }
    SHFILEINFOW sfi;
    g.icons = (HIMAGELIST)SHGetFileInfoW(L"C:\\", FILE_ATTRIBUTE_DIRECTORY, &sfi, sizeof sfi, SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
    ListView_SetImageList(g.list, g.icons, LVSIL_SMALL);
    g.status = CreateWindowW(L"STATIC", L"Waiting for the EasySuite cable…", WS_CHILD | WS_VISIBLE, 0, 0, 100, 20, g.hwnd, NULL, inst, NULL);
    SendMessageW(g.status, WM_SETFONT, (WPARAM)g.font, 1);
    DragAcceptFiles(g.hwnd, TRUE);
    ShowWindow(g.hwnd, show); UpdateWindow(g.hwnd);
    SetTimer(g.hwnd, 1, 700, NULL);
    g.thread = CreateThread(NULL, 0, cable_thread, NULL, 0, NULL);
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    g.stop = 1; es_request_stop(g.es);
    WaitForSingleObject(g.thread, 3000);
    CloseHandle(g.thread);
    es_free(g.es);
    return 0;
}
