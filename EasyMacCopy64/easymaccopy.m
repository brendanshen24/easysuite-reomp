// easymaccopy — native arm64/x86_64 replacement for the PowerPC-only "EasyMacCopy" app
// that ships with the Targus / OTi "EasySuite" USB 2.0 PC-to-Mac link cable.
//
// Everything here was recovered from the 2007 PPC binary (see README.md). Two jobs at once:
//  * server: answers the Windows EasySuite program, so the PC can browse and copy Mac files;
//  * client: shows the other computer in an EasySuite window and in Finder, through a tiny
//    WebDAV server on 127.0.0.1.
// The other computer may be Windows (EasySuite.exe, or easysuite.exe), Linux (EasySuiteLinux),
// or another Mac. Wire format matches a PowerPC Mac exactly (big-endian payload).
//
// Build: make

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/scsi/SCSITaskLib.h>
#include <NetFS/NetFS.h>
#include <libkern/OSByteOrder.h>
#include <netinet/in.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

enum {
    PKT_SIZE = 0x10000,      // every SCSI transfer moves one 64 KB packet
    PKT_HDR = 0x14,          // LE header: counter, session, index, total, dataLen
    PKT_MAX_DATA = 0xFFEC,   // payload bytes per packet
    FILE_BLOCK = 0x9F81F,    // file bytes per A3/0C block message
    OUR_OS = 0x13,           // "Mac OS X 10.3"; any value >= 8 tells the PC "Mac, big-endian"
};
static NSString *const kShare = @"EasySuite";            // Finder volume name (last URL component)
static NSString *const kLabel = @"local.easymaccopy";   // LaunchAgent label

static void say(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void say(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    fprintf(stderr, "%s\n", s.UTF8String);
}

#pragma mark - SCSI transport (MMCCommander in the original)

static SCSITaskDeviceInterface **gDev;
static MMCDeviceInterface **gMMC;
static IOCFPlugInInterface **gPlug;
static volatile sig_atomic_t gStop;
static volatile sig_atomic_t gServeDone;

// OTi status codes come back as SCSI sense data (MMCCommander getOTiSenseKeyResult:).
static int senseToOti(uint8_t key, uint8_t asc, uint8_t ascq) {
    if (key == 9 && asc >= 0x80 && asc <= 0x89 && ascq == 0) return asc;   // vendor codes 0x80-0x89
    switch (key << 16 | asc << 8 | ascq) {
        case 0x00000: return 4;
        case 0x23A00: case 0x63F0E: return 5;
        case 0x52000: case 0x72700: return 6;
        case 0x52400: return 7;
        case 0x62800: return 8;
    }
    return 0xffff;
}

// 16-byte vendor CDB with "OT" in bytes 14-15. Returns 0, an OTi code, or -1 on transport failure.
static int otiCmd(uint8_t op, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4,
                  const void *buf, uint32_t len, uint8_t dir) {
    uint8_t cdb[16] = {op, b1, b2, b3, b4};
    cdb[14] = 'O'; cdb[15] = 'T';
    SCSITaskInterface **t = (*gDev)->CreateSCSITask(gDev);
    if (!t) return -1;
    SCSI_Sense_Data sense = {0};
    SCSITaskStatus status = kSCSITaskStatus_No_Status;
    SCSIServiceResponse resp = kSCSIServiceResponse_Request_In_Process;
    UInt64 got = 0;
    IOVirtualRange range = {(IOVirtualAddress)buf, len};
    IOReturn kr = (*t)->SetCommandDescriptorBlock(t, cdb, 16);
    if (!kr && len) kr = (*t)->SetScatterGatherEntries(t, &range, 1, len, dir);
    if (!kr) kr = (*t)->SetTimeoutDuration(t, dir == kSCSIDataTransfer_FromTargetToInitiator ? 2000 : 1000);
    if (!kr) kr = (*t)->ExecuteTaskSync(t, &sense, &status, &got);
    if (!kr) kr = (*t)->GetSCSIServiceResponse(t, &resp);
    (*t)->Release(t);
    if (kr || resp != kSCSIServiceResponse_TASK_COMPLETE) return -1;
    if (status == kSCSITaskStatus_GOOD) return 0;
    if (status != kSCSITaskStatus_CHECK_CONDITION) return 0xffff;
    return senseToOti(sense.SENSE_KEY & 0xf, sense.ADDITIONAL_SENSE_CODE, sense.ADDITIONAL_SENSE_CODE_QUALIFIER);
}
#define IN  kSCSIDataTransfer_FromTargetToInitiator
#define OUT kSCSIDataTransfer_FromInitiatorToTarget
#define NONE kSCSIDataTransfer_NoDataTransfer

static io_service_t findCable(void) {
    NSArray *names = @[@"Thunder Bird", @"CROSSBOX", @"EasyCopy-Net", @"SimpleTransfer", @"SuperLink",
                       @"SUGOI CABLE EASY", @"EZ Share", @"EasyCopy", @"EasySync", @"EasySuite"];
    NSDictionary *match = @{@kIOPropertyMatchKey: @{@kIOPropertySCSITaskDeviceCategory: @kIOPropertySCSITaskAuthoringDevice}};
    io_iterator_t it;
    if (IOServiceGetMatchingServices(0, (__bridge_retained CFDictionaryRef)match, &it)) return 0;
    io_service_t svc, found = 0;
    while ((svc = IOIteratorNext(it))) {
        NSDictionary *dc = CFBridgingRelease(IORegistryEntryCreateCFProperty(svc, CFSTR("Device Characteristics"), 0, 0));
        NSDictionary *pc = CFBridgingRelease(IORegistryEntryCreateCFProperty(svc, CFSTR("Protocol Characteristics"), 0, 0));
        if (!found && [names containsObject:dc[@"Product Name"]] && [pc[@"Physical Interconnect"] isEqual:@"USB"]) found = svc;
        else IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    return found;
}

// The cable also exposes a tiny CD with the Windows installer; exclusive SCSI access is refused while it's attached.
// Disk Arbitration's unmount callback does not always fire for this device, so eject the mount directly.
static void unmountCableCD(io_service_t svc) {
    io_iterator_t it;
    if (IORegistryEntryCreateIterator(svc, kIOServicePlane, kIORegistryIterateRecursively, &it)) return;
    struct statfs *mnt = NULL;
    int n = getmntinfo(&mnt, MNT_NOWAIT);
    for (io_service_t o; (o = IOIteratorNext(it)); ) {
        if (IOObjectConformsTo(o, "IOMedia")) {
            NSString *bsd = CFBridgingRelease(IORegistryEntryCreateCFProperty(o, CFSTR("BSD Name"), 0, 0));
            if (bsd) {
                char dev[64];
                snprintf(dev, sizeof dev, "/dev/%s", bsd.UTF8String);
                for (int i = 0; i < n; i++) if (!strcmp(mnt[i].f_mntfromname, dev)) {
                    say(@"Unmounting the cable CD (%s).", mnt[i].f_mntonname);
                    if (unmount(mnt[i].f_mntonname, MNT_FORCE) && errno != EINVAL && errno != ENOENT)
                        say(@"Unmount failed: %s", strerror(errno));
                }
            }
        }
        IOObjectRelease(o);
    }
    IOObjectRelease(it);
}

// Note: the plug-in object must outlive the MMC interface, so it is only destroyed on close/failure.
static IOReturn tryOpen(io_service_t svc) {
    IOCFPlugInInterface **plug = NULL; SInt32 score; MMCDeviceInterface **mmc = NULL;
    IOReturn kr = IOCreatePlugInInterfaceForService(svc, kIOMMCDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plug, &score);
    if (kr) return kr;
    (*plug)->QueryInterface(plug, CFUUIDGetUUIDBytes(kIOMMCDeviceInterfaceID), (LPVOID *)&mmc);
    if (mmc && (gDev = (*mmc)->GetSCSITaskDeviceInterface(mmc)) && !(kr = (*gDev)->ObtainExclusiveAccess(gDev))) {
        gMMC = mmc; gPlug = plug;
        return 0;
    }
    if (gDev) (*gDev)->Release(gDev);
    if (mmc) (*mmc)->Release(mmc);
    IODestroyPlugInInterface(plug);
    gDev = NULL;
    return kr ?: kIOReturnUnsupported;
}

// After an unmount, or after another process lets go, macOS spends a moment re-attaching the
// device (and may re-claim it), so look it up afresh and keep trying for a while.
static BOOL openCable(void) {
    IOReturn kr = kIOReturnNoDevice;
    for (int i = 0; i < 100; i++) {
        io_service_t svc = findCable();
        if (svc) {
            if (gStop) return NO;
            unmountCableCD(svc);
            kr = tryOpen(svc);
            IOObjectRelease(svc);
        }
        if (!kr) return YES;
        usleep(100000);
    }
    say(@"Can't get exclusive access to the cable (0x%x). Quit any other copy of EasyMacCopy and try again.", kr);
    return NO;
}

static void closeCable(void) {
    if (gDev) { (*gDev)->ReleaseExclusiveAccess(gDev); (*gDev)->Release(gDev); gDev = NULL; }
    if (gMMC) { (*gMMC)->Release(gMMC); gMMC = NULL; }
    if (gPlug) { IODestroyPlugInInterface(gPlug); gPlug = NULL; }
}

#pragma mark - wire helpers

// Outgoing payload fields are big-endian, exactly like the PowerPC original.
static void w8(NSMutableData *d, uint8_t v) { [d appendBytes:&v length:1]; }
static void w16(NSMutableData *d, uint16_t v) { v = OSSwapHostToBigInt16(v); [d appendBytes:&v length:2]; }
static void w32(NSMutableData *d, uint32_t v) { v = OSSwapHostToBigInt32(v); [d appendBytes:&v length:4]; }
static void w64(NSMutableData *d, uint64_t v) { v = OSSwapHostToBigInt64(v); [d appendBytes:&v length:8]; }
static NSData *u16(NSString *s) { return [s dataUsingEncoding:NSUTF16BigEndianStringEncoding] ?: [NSData data]; }

// Bounds-checked reader for incoming messages; byte order follows the remote OS.
static uint8_t gRemoteOS;
static BOOL gRemoteLE = YES;   // remote writes little-endian (Windows) until it says otherwise
typedef struct { const uint8_t *p, *end; BOOL bad; } Rd;
static const uint8_t *take(Rd *r, size_t n) {
    if (r->bad || (size_t)(r->end - r->p) < n) { r->bad = YES; return NULL; }
    const uint8_t *q = r->p; r->p += n; return q;
}
static uint16_t r16(Rd *r) { const uint8_t *q = take(r, 2); return !q ? 0 : gRemoteLE ? OSReadLittleInt16(q, 0) : OSReadBigInt16(q, 0); }
static uint32_t r32(Rd *r) { const uint8_t *q = take(r, 4); return !q ? 0 : gRemoteLE ? OSReadLittleInt32(q, 0) : OSReadBigInt32(q, 0); }
static uint64_t r64(Rd *r) { const uint8_t *q = take(r, 8); return !q ? 0 : gRemoteLE ? OSReadLittleInt64(q, 0) : OSReadBigInt64(q, 0); }
static NSString *rstr(Rd *r, size_t n) {
    const uint8_t *q = take(r, n);
    NSString *s = q ? [[NSString alloc] initWithBytes:q length:n encoding:gRemoteLE ? NSUTF16LittleEndianStringEncoding : NSUTF16BigEndianStringEncoding] : nil;
    if (!s) r->bad = YES;
    return s;
}

#pragma mark - packets (OTiPacket / sendCommandDataOut / ReceivingBlocks)

// All protocol state below is guarded by gCond. The cable thread holds it while it works;
// Finder (WebDAV) threads take it to queue requests and wait on it for replies.
static NSCondition *gCond;
static NSMutableArray<NSData *> *gTx;   // queued 64 KB packets
static uint32_t gPktCounter, gSessionCtr;
static NSUInteger gBooking = 15, gMaxTx = 45;
static NSDate *gActivity;               // last time a packet moved

static uint32_t newSession(void) { return ++gSessionCtr; }

static void sendMsg(NSData *msg, uint32_t session) {
    NSUInteger len = msg.length, total = MAX(1, (len + PKT_MAX_DATA - 1) / PKT_MAX_DATA);
    for (NSUInteger i = 0; i < total; i++) {
        NSUInteger off = i * PKT_MAX_DATA, n = MIN(PKT_MAX_DATA, len - off);
        NSMutableData *p = [NSMutableData dataWithLength:PKT_SIZE];
        uint8_t *b = p.mutableBytes;
        OSWriteLittleInt32(b, 0, gPktCounter++);
        OSWriteLittleInt32(b, 4, session);
        OSWriteLittleInt32(b, 8, (uint32_t)i);
        OSWriteLittleInt32(b, 12, (uint32_t)total);
        OSWriteLittleInt32(b, 16, (uint32_t)n);
        memcpy(b + PKT_HDR, (const uint8_t *)msg.bytes + off, n);
        [gTx addObject:p];
    }
}

static NSMutableDictionary<NSNumber *, NSMutableData *> *gRxBuf;
static NSMutableDictionary<NSNumber *, NSNumber *> *gRxCount;

// Feed one received packet; returns the whole message once its last piece arrives.
static NSData *reassemble(const uint8_t *p, uint32_t *session) {
    uint32_t s = OSReadLittleInt32(p, 4), idx = OSReadLittleInt32(p, 8), total = OSReadLittleInt32(p, 12), n = OSReadLittleInt32(p, 16);
    if (n > PKT_MAX_DATA || total == 0) return nil;
    *session = s;
    if (total == 1) return [NSData dataWithBytes:p + PKT_HDR length:n];
    NSNumber *k = @(s);
    if (!gRxBuf[k] || idx == 0) { gRxBuf[k] = [NSMutableData data]; gRxCount[k] = @0; }
    [gRxBuf[k] appendBytes:p + PKT_HDR length:n];
    gRxCount[k] = @(gRxCount[k].unsignedIntValue + 1);
    if (gRxCount[k].unsignedIntValue != total) return nil;
    NSData *m = gRxBuf[k];
    [gRxBuf removeObjectForKey:k]; [gRxCount removeObjectForKey:k];
    return m;
}

#pragma mark - server replies (OTiServer / ThunderBirdController)

// A1 command result. `sess` is 0 except for login, where the original wrote its OS code into all four bytes.
static void replyResult(uint8_t cmd, uint8_t result, uint32_t err, uint32_t sess) {
    NSMutableData *m = [NSMutableData data];
    w8(m, 0xA1); w8(m, cmd); w8(m, result); w32(m, sess); w32(m, err); w64(m, 0); w8(m, 0); w32(m, 0);
    sendMsg(m, newSession());
}

// A9 (download read failed) / A5 (upload write failed): [cmd][id][errno]"ErrStr"[len][UTF-16 text]
static void replyError(uint8_t cmd, uint32_t session, int err, BOOL withFileID, uint32_t fileID) {
    NSString *text = err ? @(strerror(err)) : @"Overwriting File was Readonly or Locked";
    NSData *t = u16(text);
    NSMutableData *m = [NSMutableData data];
    w8(m, cmd); w32(m, session); w32(m, err);
    if (withFileID) w32(m, fileID);
    [m appendBytes:"ErrStr" length:6]; w32(m, (uint32_t)t.length); [m appendData:t];
    sendMsg(m, newSession());
}

static void replyFinish(uint32_t session) {   // A7: all files of a download sent
    NSMutableData *m = [NSMutableData data]; w8(m, 0xA7); w32(m, session);
    sendMsg(m, newSession());
}

// One 552-byte ListItem: attr, ctime, atime, mtime, size, nameLen, UTF-16 name[256].
static BOOL appendDirEntry(NSMutableData *out, NSString *dir, NSString *name) {
    NSString *full = [dir stringByAppendingPathComponent:name];
    struct stat st;
    if (lstat(full.fileSystemRepresentation, &st) < 0) return NO;
    NSFileManager *fm = NSFileManager.defaultManager;
    BOOL writable = [fm isWritableFileAtPath:full], link = S_ISLNK(st.st_mode), isDir = NO;
    uint32_t attr = 0;                                   // Windows FILE_ATTRIBUTE_* bits
    if (!writable) attr |= 0x1;
    if (link) attr |= 0x10000;
    if (writable && !link) attr |= 0x80;
    if ([fm fileExistsAtPath:full isDirectory:&isDir] && isDir) attr |= 0x10;
    NSData *nm = u16(name);
    if (nm.length > 512) nm = [nm subdataWithRange:NSMakeRange(0, 512)];
    w32(out, attr);
    w64(out, st.st_birthtimespec.tv_sec);
    w64(out, st.st_atimespec.tv_sec);
    w64(out, st.st_mtimespec.tv_sec);
    w64(out, st.st_size);
    w32(out, (uint32_t)nm.length);
    [out appendData:nm];
    [out increaseLengthBy:512 - nm.length];
    return YES;
}

static void replyDir(NSString *path, uint32_t session) {   // A2
    NSSet *rootHidden = [NSSet setWithObjects:@"cores", @"sbin", @"resources", @"private", @"automount", @"etc", nil];
    NSMutableData *items = [NSMutableData data];
    uint16_t n = 0;
    for (NSString *name in [NSFileManager.defaultManager contentsOfDirectoryAtPath:path error:nil]) {
        if ([name hasPrefix:@"."] || ([path isEqual:@"/"] && [rootHidden containsObject:name])) continue;
        if (n < 0xFFFF && appendDirEntry(items, path, name)) n++;
    }
    NSMutableData *m = [NSMutableData data]; w8(m, 0xA2); w16(m, n); [m appendData:items];
    sendMsg(m, session);
}

static void replyVolumes(void) {   // A4: mounted volumes + the original's shortcut folders
    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableArray<NSArray *> *vols = [NSMutableArray array];   // @[type, display name, path]
    for (NSURL *u in [fm mountedVolumeURLsIncludingResourceValuesForKeys:nil options:NSVolumeEnumerationSkipHiddenVolumes]) {
        struct statfs sf;
        if (statfs(u.fileSystemRepresentation, &sf)) continue;
        if (!strcmp(sf.f_fstypename, "webdav")) continue;                         // don't offer the PC its own drives back
        uint8_t type = 0x12;                                                      // hard disk
        if (!(sf.f_flags & MNT_LOCAL)) type = 0x13;                               // network
        else if (!strcmp(sf.f_fstypename, "cd9660") || !strcmp(sf.f_fstypename, "udf") || !strcmp(sf.f_fstypename, "cddafs")) type = 0x14;
        else {                                                                    // removable / FAT
            NSNumber *removable = nil; [u getResourceValue:&removable forKey:NSURLVolumeIsRemovableKey error:nil];
            if (removable.boolValue || !strcmp(sf.f_fstypename, "msdos") || !strcmp(sf.f_fstypename, "exfat")) type = 0x11;
        }
        [vols addObject:@[@(type), [fm displayNameAtPath:u.path], u.path]];
    }
    NSString *home = NSHomeDirectory();
    for (NSString *p in @[@"/Network", [home stringByAppendingString:@"/Desktop"], home, @"/Applications",
                          [home stringByAppendingString:@"/Documents"], [home stringByAppendingString:@"/Movies"],
                          [home stringByAppendingString:@"/Music"], [home stringByAppendingString:@"/Pictures"]])
        if ([fm fileExistsAtPath:p]) [vols addObject:@[@0x16, [fm displayNameAtPath:p], p]];

    NSMutableData *m = [NSMutableData data];
    uint16_t count = OSSwapHostToLittleInt16((uint16_t)vols.count);   // the one field the original sent little-endian
    w8(m, 0xA4); [m appendBytes:&count length:2];
    for (NSArray *v in vols) { w8(m, 'A'); w8(m, [v[0] unsignedCharValue]); }
    for (NSArray *v in vols) {
        NSData *name = u16(v[1]), *path = u16(v[2]);
        w16(m, (uint16_t)name.length); [m appendData:name];
        w16(m, (uint16_t)path.length); [m appendData:path];
    }
    sendMsg(m, newSession());
}

#pragma mark - server downloads: Mac -> PC (GenBulkDataServerObject)

@interface Job : NSObject { @public uint32_t session; NSMutableArray<NSArray *> *files; NSUInteger idx; int fd; uint64_t size, sent; uint32_t blocks, block; }
@end
@implementation Job
@end
static NSMutableArray<Job *> *gJobs;
static NSMutableData *msgBlock(uint8_t cmd, uint32_t fid, uint32_t blocks, uint32_t index, uint32_t n);

static void dropJob(Job *j) { if (j->fd >= 0) close(j->fd); [gJobs removeObject:j]; }

// Turn queued download requests into A3 block messages while the transmit queue has room.
static void pumpDownloads(void) {
    while (gJobs.count && gTx.count < gMaxTx) {
        Job *j = gJobs[0];
        uint32_t fid = [j->files[j->idx][0] unsignedIntValue];
        if (j->fd < 0) {
            NSString *path = j->files[j->idx][1];
            struct stat st;
            j->fd = open(path.fileSystemRepresentation, O_RDONLY);
            if (j->fd < 0 || fstat(j->fd, &st) < 0) { replyError(0xA9, j->session, errno, YES, fid); dropJob(j); continue; }
            j->size = st.st_size; j->sent = 0; j->block = 0;
            j->blocks = (uint32_t)MAX(1, (j->size + FILE_BLOCK - 1) / FILE_BLOCK);
            say(@"→ PC  %@ (%llu bytes)", path, j->size);
        }
        uint32_t n = (uint32_t)MIN((uint64_t)FILE_BLOCK, j->size - j->sent);
        NSMutableData *m = msgBlock(0xA3, fid, j->blocks, j->block + 1, n);
        ssize_t got = pread(j->fd, (uint8_t *)m.mutableBytes + 17, n, (off_t)j->sent);
        if (got != (ssize_t)n) { replyError(0xA9, j->session, got < 0 ? errno : EIO, YES, fid); dropJob(j); continue; }
        sendMsg(m, newSession());
        j->sent += n;
        if (++j->block < j->blocks) continue;
        close(j->fd); j->fd = -1;
        if (++j->idx == j->files.count) { replyFinish(j->session); [gJobs removeObject:j]; }
    }
}

#pragma mark - server uploads: PC -> Mac (handleSavingFile / MultiTransferForRemoteUploadSession)

static uint32_t gUpSession;
static NSDictionary<NSNumber *, NSString *> *gUpFiles;   // fileID -> destination path
static int gUpFd = -1;
static NSString *gUpPath;
static BOOL gUpCancelled;

static void closeUpload(void) { if (gUpFd >= 0) close(gUpFd); gUpFd = -1; }

static void uploadBlock(Rd *r) {
    uint32_t fid = r32(r), total = r32(r), idx = r32(r), n = r32(r);
    const uint8_t *data = take(r, n);
    NSString *path = gUpFiles[@(fid)];
    if (r->bad || !path || gUpCancelled) return;
    if (idx == 1) {
        closeUpload();
        NSDictionary *a = [NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
        if ([a[NSFileImmutable] boolValue]) { replyError(0xA5, gUpSession, 0, NO, 0); return; }
        gUpFd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC, 0644);   // original forgot O_TRUNC
        if (gUpFd < 0) { replyError(0xA5, gUpSession, errno, NO, 0); return; }
        gUpPath = path;
        say(@"← PC  %@", path);
    }
    if (gUpFd < 0) return;
    if (write(gUpFd, data, n) != (ssize_t)n) { replyError(0xA5, gUpSession, errno ?: ENOSPC, NO, 0); closeUpload(); return; }
    if (idx == total) closeUpload();
}

#pragma mark - client state: the Mac asking the PC (OTiClient)

static uint16_t gBus;          // hi byte: our USB speed, lo byte: remote (0x20 = USB 2.0)
static NSString *peerKind(void) {
    if (gRemoteOS == 0x14) return @"Linux";
    return gRemoteLE ? @"Windows" : @"Mac";
}
static BOOL gLoggedIn;         // we are logged in to the PC's EasySuite
static NSDate *gLoginSent, *gLoginTime;
static uint32_t gConnGen;      // bumps whenever the PC side goes away
static NSArray<NSDictionary *> *gRoots;   // @{id, name, root} for the other computer's volumes
static NSData *gVolRaw;                      // last A4, parsed once we know which OS is on the far side

static BOOL gGot[256]; static uint8_t gRes[256]; static uint32_t gErr[256];   // latest A1 per request command
static BOOL gWantDir; static NSData *gDirReply;                                // A2
static BOOL gWantA8; static NSData *gA8;                                       // A8 upload pre-check
static int gDlFd = -1; static uint32_t gDlSession; static uint64_t gDlBytes; static BOOL gDlDone, gDlFailed;
static uint32_t gUlSession; static BOOL gUlFailed;

static NSString *gMountPoint; static BOOL gMounting, gMountFailed;
static int gHttpPort;

static void adjustBooking(void) {
    if (gBus == 0x2020) gBooking = gRemoteOS - 3u < 2 ? 50 : 100;
    gMaxTx = gBooking * 3;
}

// A4 count is little-endian from both a Mac and a PC. Paths after the letter/type pairs are in the
// remote's own byte order. Windows roots are "C:\"; Mac roots are the POSIX paths from the list.
static NSString *cleanId(NSString *s) {
    NSString *t = [[s componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/\\:"]] componentsJoinedByString:@" "];
    t = [t stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    return t.length ? t : @"Volume";
}
static void applyVols(void) {
    if (!gVolRaw || gVolRaw.length < 3 || !gRemoteOS) return;
    const uint8_t *d = gVolRaw.bytes;
    uint16_t c = OSReadLittleInt16(d, 1);
    if ((size_t)(3 + 2 * c) > gVolRaw.length) return;
    Rd r = {d + 3 + 2 * c, d + gVolRaw.length, NO};
    NSMutableArray *roots = [NSMutableArray array];
    NSMutableSet *ids = [NSMutableSet set];
    for (uint16_t i = 0; i < c; i++) {
        unsigned char letter = d[3 + 2 * i];
        NSString *name = nil, *path = nil;
        if (r.p < r.end && !r.bad) {
            uint16_t nl = r16(&r); name = rstr(&r, nl);
            uint16_t pl = r16(&r); path = rstr(&r, pl);
            if (r.bad) name = path = nil;
        }
        NSString *root = nil, *ident = nil, *shown = nil;
        if (gRemoteLE) {
            if (letter < 'C' || letter > 'Z') continue;
            ident = [NSString stringWithFormat:@"%c", letter];
            root = [ident stringByAppendingString:@":\\"];
            shown = name.length ? name : ident;
        } else if (path.length) {
            root = path;
            shown = name.length ? name : path.lastPathComponent;
            if (!shown.length) shown = @"Macintosh HD";
            ident = cleanId(shown);
        }
        if (!root) continue;
        NSString *unique = ident;
        for (int n = 2; [ids containsObject:unique]; n++) unique = [NSString stringWithFormat:@"%@ %d", ident, n];
        [ids addObject:unique];
        [roots addObject:@{@"id": unique, @"name": shown, @"root": root}];
    }
    if (roots.count) gRoots = roots;
}

#pragma mark - dispatch (DecodingPacketServerObject decodeClientCmd / decodeServerCmd)

// Reads the {u32 id, u16 len, UTF-16 path} list used by several requests.
static NSArray<NSArray *> *readFileList(Rd *r, uint16_t count) {
    NSMutableArray *list = [NSMutableArray array];
    for (uint16_t i = 0; i < count && !r->bad; i++) {
        uint32_t fid = r32(r); uint16_t len = r16(r);
        NSString *p = rstr(r, len);
        if (p) [list addObject:@[@(fid), p]];
    }
    return r->bad ? nil : list;
}

static void dispatch(NSData *msg, uint32_t pktSession) {
    if (!msg.length) return;
    const uint8_t *d = msg.bytes;
    Rd r = {d + 1, d + msg.length, NO};
    NSFileManager *fm = NSFileManager.defaultManager;
    switch (d[0]) {
    // ---- requests from the PC (we are the server) ----
    case 0x01: {                                   // login from the PC
        if (msg.length < 2) return;
        gRemoteOS = d[1]; gRemoteLE = gRemoteOS < 8;
        say(@"%@ connected (OS code %u).", peerKind(), gRemoteOS);
        replyResult(0x01, 0, 0, OUR_OS * 0x01010101u);
        replyVolumes();
        adjustBooking();
        applyVols();
        break;
    }
    case 0x04: {                                   // list a directory
        uint16_t len = r16(&r); NSString *path = rstr(&r, len);
        if (r.bad) return;
        replyResult(0x04, 0, 0, 0);
        replyDir(path, pktSession);
        break;
    }
    case 0x06: case 0x08: {                        // delete folder / file (to the Trash, like the original)
        r32(&r); uint16_t len = r16(&r); NSString *path = rstr(&r, len);
        if (r.bad) return;
        BOOL ok = [fm trashItemAtURL:[NSURL fileURLWithPath:path] resultingItemURL:nil error:nil];
        say(@"PC deleted %@%@", path, ok ? @"" : @" (failed)");
        replyResult(d[0], ok ? 0 : 1, 0, 0);
        break;
    }
    case 0x07: {                                   // make directory
        r32(&r); uint16_t len = r16(&r); NSString *path = rstr(&r, len);
        if (r.bad) return;
        BOOL ok = ![fm fileExistsAtPath:path] && [fm createDirectoryAtPath:path withIntermediateDirectories:NO attributes:nil error:nil];
        replyResult(0x07, ok ? 0 : 1, ok ? 0 : EEXIST, 0);
        break;
    }
    case 0x09: {                                   // rename
        r32(&r); uint16_t l1 = r16(&r), l2 = r16(&r);
        NSString *from = rstr(&r, l1), *to = rstr(&r, l2);
        if (r.bad) return;
        BOOL ok = [fm moveItemAtPath:from toPath:to error:nil];
        replyResult(0x09, ok ? 0 : 1, ok ? 0 : EEXIST, 0);
        break;
    }
    case 0x0C: uploadBlock(&r); break;             // file data PC -> Mac
    case 0x10: {                                   // PC wants files from the Mac
        uint32_t s = r32(&r); uint16_t c = r16(&r);
        NSArray<NSArray *> *list = readFileList(&r, c);
        if (!list) return;
        Job *j = [Job new]; j->session = s; j->files = [NSMutableArray array]; j->fd = -1;
        NSMutableData *zeros = [NSMutableData data]; uint16_t nz = 0;
        for (NSArray *f in list) {
            struct stat st;
            if (lstat([f[1] fileSystemRepresentation], &st) < 0) {
                int e = errno;
                replyError(0xA9, s, e, YES, [f[0] unsignedIntValue]);
                replyResult(0x10, 1, e, 0);
                return;
            }
            if (st.st_size == 0) { w32(zeros, [f[0] unsignedIntValue]); nz++; }
            else [j->files addObject:f];
        }
        replyResult(0x10, 0, 0, 0);
        if (nz) { NSMutableData *m = [NSMutableData data]; w8(m, 0xA6); w32(m, s); w16(m, nz); [m appendData:zeros]; sendMsg(m, newSession()); }
        if (j->files.count) [gJobs addObject:j];
        else if (s) replyFinish(s);
        break;
    }
    case 0x11: {                                   // PC cancelled a download
        uint32_t s = r32(&r);
        for (Job *j in gJobs.copy) if (j->session == s) dropJob(j);
        break;
    }
    case 0x12: {                                   // upload file list (fileID -> destination)
        uint32_t s = r32(&r); uint16_t c = r16(&r);
        NSArray<NSArray *> *list = readFileList(&r, c);
        if (!list) return;
        NSMutableDictionary *files = [NSMutableDictionary dictionary];
        for (NSArray *f in list) files[f[0]] = f[1];
        closeUpload();
        gUpSession = s; gUpFiles = files; gUpCancelled = NO;
        break;
    }
    case 0x13: {                                   // upload pre-check: which files exist, is there room
        uint32_t s = r32(&r); uint64_t total = r64(&r); r16(&r); uint16_t c = r16(&r);
        NSArray<NSArray *> *list = readFileList(&r, c);
        if (!list) return;
        NSMutableData *exist = [NSMutableData data]; uint32_t ne = 0;
        for (NSArray *f in list) if ([fm fileExistsAtPath:f[1]]) { w32(exist, [f[0] unsignedIntValue]); ne++; }
        NSString *probe = list.count ? list[0][1] : @"/";
        while (probe.length > 1 && ![fm fileExistsAtPath:probe]) probe = probe.stringByDeletingLastPathComponent;
        struct statfs sf = {0};
        statfs(probe.fileSystemRepresentation, &sf);
        uint64_t free = (uint64_t)sf.f_bavail * sf.f_bsize;
        NSMutableData *m = [NSMutableData data];
        w8(m, 0xA8); w8(m, 0); w8(m, total < free); w8(m, 1); w8(m, (sf.f_flags & MNT_RDONLY) != 0);
        w32(m, s); w32(m, ne); [m appendData:exist];
        sendMsg(m, newSession());
        break;
    }
    case 0x14: {                                   // PC cancelled an upload: drop the partial file
        if (r32(&r) != gUpSession || r.bad) return;
        gUpCancelled = YES;
        if (gUpFd >= 0) { closeUpload(); [fm trashItemAtURL:[NSURL fileURLWithPath:gUpPath] resultingItemURL:nil error:nil]; }
        break;
    }
    case 0x15: {                                   // empty files: just create them
        r32(&r); uint16_t c = r16(&r);
        for (NSArray *f in readFileList(&r, c)) [fm createFileAtPath:f[1] contents:nil attributes:nil];
        break;
    }
    case 0x37: {                                   // set permissions / dates
        uint32_t mode = r32(&r); uint64_t ctime = r64(&r), mtime = r64(&r); r64(&r);
        uint32_t len = r32(&r); NSString *path = rstr(&r, len);
        if (r.bad) return;
        NSMutableDictionary *a = [@{NSFileCreationDate: [NSDate dateWithTimeIntervalSince1970:ctime],
                                    NSFileModificationDate: [NSDate dateWithTimeIntervalSince1970:mtime]} mutableCopy];
        if (!gRemoteLE) a[NSFilePosixPermissions] = @(mode & 0xFFFF);
        [fm setAttributes:a ofItemAtPath:path error:nil];
        break;
    }
    // ---- replies from the PC (we are the client) ----
    case 0xA1: {                                   // [cmd][result][4 bytes][errno]...
        if (msg.length < 11) return;
        uint8_t cmd = d[1];
        if (cmd == 0x01) {                         // our login: the PC repeats its OS code in bytes 3-6
            if (d[3] && d[3] != 0xFF && d[3] == d[4] && d[3] == d[5] && d[3] == d[6]) { gRemoteOS = d[3]; gRemoteLE = gRemoteOS < 8; }
            if (d[2] == 0 && !gLoggedIn) {
                gLoggedIn = YES; gLoginTime = [NSDate date]; adjustBooking(); applyVols();
                say(@"Logged in to the other computer (%@).", peerKind());
            }
        }
        Rd e = {d + 7, d + msg.length, NO};
        gGot[cmd] = YES; gRes[cmd] = d[2]; gErr[cmd] = r32(&e);
        break;
    }
    case 0xA2: if (gWantDir) gDirReply = msg; break;
    case 0xA3: {                                   // file block for our download
        uint32_t fid = r32(&r); r32(&r); r32(&r); uint32_t n = r32(&r);
        const uint8_t *p = take(&r, n);
        if (r.bad || gDlFd < 0 || fid != gDlSession || gDlFailed) break;
        if (pwrite(gDlFd, p, n, (off_t)gDlBytes) != (ssize_t)n) gDlFailed = YES;
        else gDlBytes += n;
        break;
    }
    case 0xA4: gVolRaw = msg; applyVols(); break;
    case 0xA5: if (r32(&r) == gUlSession && !r.bad) gUlFailed = YES; break;   // PC couldn't save our upload
    case 0xA7: if (r32(&r) == gDlSession && !r.bad) gDlDone = YES; break;     // download finished
    case 0xA8: if (gWantA8) gA8 = msg; break;
    case 0xA9: if (r32(&r) == gDlSession && !r.bad) gDlFailed = YES; break;   // PC couldn't read the file
    default: break;                                // logout, other replies: nothing to do
    }
}

#pragma mark - Finder volume (NetFS mounts our WebDAV server)

static void mountFinderVolume(void) {
    @autoreleasepool {
        NSString *s = [NSString stringWithFormat:@"http://127.0.0.1:%d/%@/", gHttpPort,
                       [kShare stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLPathAllowedCharacterSet]];
        NSMutableDictionary *open = [@{(__bridge id)kNAUIOptionKey: (__bridge id)kNAUIOptionNoUI,
                                       (__bridge id)kNetFSUseGuestKey: @YES} mutableCopy];
        CFArrayRef mps = NULL;
        int rc = NetFSMountURLSync((__bridge CFURLRef)[NSURL URLWithString:s], NULL, NULL, NULL,
                                   (__bridge CFMutableDictionaryRef)open, NULL, &mps);
        NSArray *points = CFBridgingRelease(mps);
        [gCond lock];
        gMounting = NO;
        if (!rc && points.count) { gMountPoint = points[0]; say(@"The other computer is in Finder at %@", gMountPoint); }
        else { gMountFailed = YES; say(@"Couldn't show the other computer in Finder (NetFS error %d).", rc); }
        [gCond unlock];
    }
}

// Caller holds gCond. Returns the mount point to pass to unmountPath() once the lock is released.
static NSString *takeMountPoint(void) { NSString *mp = gMountPoint; gMountPoint = nil; return mp; }
static void unmountPath(NSString *mp) {
    if (!mp) return;
    say(@"Removing the other computer from Finder.");
    unmount(mp.fileSystemRepresentation, MNT_FORCE);   // the PC is gone, so pending I/O can only fail anyway
}
static void unmountLater(NSString *mp) { if (mp) dispatch_async(dispatch_get_global_queue(0, 0), ^{ unmountPath(mp); }); }

static NSDate *gMountTried;

static void maybeMount(void) {   // caller holds gCond
    if (!gLoggedIn || gMountPoint || gMounting || !gHttpPort) return;
    if (gMountFailed && gMountTried && -gMountTried.timeIntervalSinceNow < 30) return;
    if (!gRoots.count && gRemoteLE && gLoginTime && -gLoginTime.timeIntervalSinceNow > 5)
        gRoots = @[@{@"id": @"C", @"name": @"C", @"root": @"C:\\"}];   // Windows never sent a drive list
    if (!gRoots.count) return;
    gMountFailed = NO;
    gMounting = YES;
    gMountTried = [NSDate date];
    [NSThread detachNewThreadWithBlock:^{ mountFinderVolume(); }];
}

#pragma mark - polling loop (BookingServerObject)

static void onSignal(int sig) { (void)sig; gStop = 1; }

static void sendLogin(void) {
    NSMutableData *m = [NSMutableData data];
    w8(m, 0x01); w8(m, OUR_OS); w8(m, 0); w8(m, 0); w8(m, 6); [m appendBytes:"MACOSX" length:6];
    sendMsg(m, newSession());
    gLoginSent = [NSDate date];
}

static void remoteGone(void) {   // caller holds gCond
    if (gLoggedIn) say(@"The other computer closed EasySuite.");
    if (gLoggedIn || gLoginSent) gConnGen++;
    gLoggedIn = NO; gLoginSent = nil; gRoots = nil; gVolRaw = nil; gMountFailed = NO;
    [gTx removeAllObjects];
    for (Job *j in gJobs.copy) dropJob(j);
    closeUpload(); gUpFiles = nil;
    unmountLater(takeMountPoint());
}

// Send up to n queued packets; returns the last OTi code (0 = all sent).
static int transmit(NSUInteger n) {
    int rc = 0;
    for (NSUInteger i = 0, retry = 0; i < n && gTx.count && !gStop; ) {
        rc = otiCmd(0xD9, 0x2A, 0xFF, 0, 0, gTx[0].bytes, PKT_SIZE, OUT);
        if (rc == 0) { [gTx removeObjectAtIndex:0]; i++; retry = 0; gActivity = [NSDate date]; continue; }
        if ((rc == 0x87 || rc == 0x88 || rc == 0x89) && ++retry < 100) continue;   // device busy: retry same packet
        break;
    }
    return rc;
}

// Runs until the cable goes away or we're asked to stop.
static void serveCable(void) {
    NSMutableData *rx = [NSMutableData dataWithLength:PKT_SIZE];
    double nap = 0;
    int failures = 0;
    unsigned contTx = 0;
    BOOL lost = NO;
    say(@"Waiting for EasySuite on the other computer… (Ctrl-C to quit)");
    while (!gStop && !lost) {
        [gCond lock];
        @autoreleasepool {
            pumpDownloads();
            uint16_t want = (uint16_t)MIN(gTx.count, gBooking);
            if (contTx >= 11) { contTx = 0; want = 0; }    // let the PC talk too
            uint8_t st[8] = {0};
            if (otiCmd(0xD8, 0, 3, want >> 8, want & 0xFF, st, sizeof st, IN) < 0) {
                lost = ++failures >= 3;
                nap = 0.2;
            } else {
                failures = 0;
                BOOL present = st[0] >= 5 && st[0] <= 7;
                if (present && !gLoggedIn && (!gLoginSent || -gLoginSent.timeIntervalSinceNow > 5)) sendLogin();
                switch (st[0]) {
                case 0: case 1: remoteGone(); nap = 0.05; break;
                case 2: case 3: break;
                case 5: {                              // PC has packets for us
                    contTx = 0; nap = 0;
                    for (unsigned n = st[1] << 8 | st[2]; n; n--) {
                        int rc = otiCmd(0xD9, 0x28, 0x64, 0, 0, rx.mutableBytes, PKT_SIZE, IN);
                        if (rc) { nap = rc == 1 ? 0.1 : (rc == 0x83 || rc == 0x84) ? 0 : 0.001; break; }
                        gActivity = [NSDate date];
                        uint32_t s; NSData *m = reassemble(rx.bytes, &s);
                        if (m) dispatch(m, s);
                    }
                    break;
                }
                case 6: case 7: {                      // we may send
                    if (st[0] == 7 && !want) { contTx = 0; nap = gTx.count ? 0 : 0.3; break; }
                    contTx++;
                    int rc = transmit(st[0] == 6 ? 1 : want);
                    nap = (rc == 0 || rc == 0x85 || rc == 0x86) ? 0 : rc == 1 ? 0.1 : 0.005;
                    break;
                }
                default: nap = 0.005; break;
                }
                maybeMount();
            }
        }
        [gCond broadcast];
        [gCond unlock];
        if (nap > 0 && !lost) usleep((useconds_t)(nap * 1e6));
    }
    if (lost) say(@"Lost the cable.");
}

#pragma mark - client requests (called from WebDAV threads)

static NSLock *gCtlLock;    // one listing/mkdir/delete/rename at a time (also guards the listing cache)
static NSLock *gXferLock;   // one file transfer at a time

// Outgoing client requests. Layouts are the PowerPC app's (big-endian fields, big-endian UTF-16).
static NSMutableData *msgBlock(uint8_t cmd, uint32_t fid, uint32_t blocks, uint32_t index, uint32_t n) {
    NSMutableData *m = [NSMutableData dataWithCapacity:17 + n];
    w8(m, cmd); w32(m, fid); w32(m, blocks); w32(m, index); w32(m, n);
    [m increaseLengthBy:n];
    return m;
}
static NSData *msgList(NSString *dir) {
    NSData *p = u16(dir);
    NSMutableData *m = [NSMutableData data];
    w8(m, 0x04); w16(m, (uint16_t)p.length); [m appendData:p];
    return m;
}
static NSData *msgPaths(uint8_t cmd, uint32_t sess, NSString *path, NSString *path2) {
    NSData *a = u16(path), *b = path2 ? u16(path2) : nil;
    NSMutableData *m = [NSMutableData data];
    w8(m, cmd); w32(m, sess); w16(m, (uint16_t)a.length);
    if (b) w16(m, (uint16_t)b.length);
    [m appendData:a]; if (b) [m appendData:b];
    return m;
}
static NSData *msgFiles(uint8_t cmd, uint32_t sess, uint32_t fid, NSString *path) {
    NSData *p = u16(path);
    NSMutableData *m = [NSMutableData data];
    w8(m, cmd); w32(m, sess); w16(m, 1); w32(m, fid); w16(m, (uint16_t)p.length); [m appendData:p];
    return m;
}
static NSData *msgConfirm(uint32_t sess, uint32_t fid, uint64_t size, NSString *path) {
    NSData *p = u16(path);
    NSMutableData *m = [NSMutableData data];
    w8(m, 0x13); w32(m, sess); w64(m, size); w16(m, 0); w16(m, 1);   // largeFileCount stays 0
    w32(m, fid); w16(m, (uint16_t)p.length); [m appendData:p];
    return m;
}

// Caller holds gCond. Waits until done() — or until the PC disconnects / goes quiet for 30 s.
static BOOL waitFor(BOOL (^done)(void)) {
    uint32_t gen = gConnGen;
    gActivity = [NSDate date];
    while (!done()) {
        if (gConnGen != gen || !gLoggedIn || -gActivity.timeIntervalSinceNow > 30) return NO;
        [gCond waitUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.5]];
    }
    return YES;
}

// 06 / 07 / 08 / 09 request; returns the PC's result byte (0 = ok), or -1 if it didn't answer.
static int pcRequest(uint8_t cmd, NSString *path, NSString *path2) {
    [gCond lock];
    int rc = -1;
    if (gLoggedIn) {
        uint32_t s = newSession();
        gGot[cmd] = NO;
        sendMsg(msgPaths(cmd, s, path, path2), s);
        if (waitFor(^{ return gGot[cmd]; })) rc = gRes[cmd];
    }
    [gCond unlock];
    return rc;
}

// A2 reply -> @[{name, dir, size, mtime, ctime}]. Caller holds gCond (byte order).
static NSArray<NSDictionary *> *parseDirReply(NSData *msg) {
    Rd r = {(const uint8_t *)msg.bytes + 1, (const uint8_t *)msg.bytes + msg.length, NO};
    uint16_t n = r16(&r);
    NSMutableArray *out = [NSMutableArray array];
    for (uint16_t i = 0; i < n; i++) {
        const uint8_t *e = take(&r, 0x228);
        if (!e) break;
        Rd f = {e, e + 0x228, NO};
        uint32_t attr = r32(&f); uint64_t ctime = r64(&f); r64(&f); uint64_t mtime = r64(&f), size = r64(&f);
        uint32_t len = MIN(r32(&f), 512u) & ~1u;
        NSString *name = rstr(&f, len);
        if (!name.length || [name isEqual:@"."] || [name isEqual:@".."]) continue;
        // times are Unix seconds; convert if a PC ever sends Windows FILETIME instead
        if (mtime > 100000000000ULL) mtime = mtime / 10000000 - 11644473600ULL;
        if (ctime > 100000000000ULL) ctime = ctime / 10000000 - 11644473600ULL;
        [out addObject:@{@"name": name, @"dir": @((attr & 0x10) != 0), @"size": @(size), @"mtime": @(mtime), @"ctime": @(ctime)}];
    }
    return out;
}

static NSArray<NSDictionary *> *pcList(NSString *dir) {   // nil if the PC refused or didn't answer
    [gCond lock];
    NSArray *list = nil;
    if (gLoggedIn) {
        gGot[4] = NO; gDirReply = nil; gWantDir = YES;
        sendMsg(msgList(dir), 0);
        if (waitFor(^{ return (BOOL)(gDirReply != nil || (gGot[4] && gRes[4] != 0)); }) && gDirReply) list = parseDirReply(gDirReply);
        gWantDir = NO; gDirReply = nil;
    }
    [gCond unlock];
    return list;
}

// Paths on the wire. Windows: "C:\" and "C:\dir\file". Mac: "/" and "/Volumes/HD/dir".
static NSString *wireSep(NSString *dir) {
    if ([dir containsString:@"\\"] || (dir.length >= 2 && [dir characterAtIndex:1] == ':')) return @"\\";
    return @"/";
}
static NSString *pcParent(NSString *p) {
    if ([wireSep(p) isEqual:@"\\"]) {
        NSUInteger i = [p rangeOfString:@"\\" options:NSBackwardsSearch].location;
        if (i == NSNotFound || i <= 2) return p.length >= 3 ? [p substringToIndex:3] : p;
        return [p substringToIndex:i];
    }
    if (p.length <= 1) return @"/";
    NSString *par = p.stringByDeletingLastPathComponent;
    return par.length ? par : @"/";
}
static NSString *pcJoin(NSString *dir, NSString *name) {
    NSString *sep = wireSep(dir);
    if ([dir isEqual:@"/"]) return [@"/" stringByAppendingString:name];
    if ([dir hasSuffix:sep]) return [dir stringByAppendingString:name];
    return [dir stringByAppendingFormat:@"%@%@", sep, name];
}

// Finder asks the same things over and over; listings are kept for a few seconds. Caller holds gCtlLock.
static NSMutableDictionary<NSString *, NSArray *> *gCache;
static NSMutableDictionary<NSString *, NSDate *> *gCacheTime;
static NSArray<NSDictionary *> *listCached(NSString *dir) {
    NSString *k = dir.lowercaseString;
    if (gCache[k] && -gCacheTime[k].timeIntervalSinceNow < 3) return gCache[k];
    NSArray *l = pcList(dir);
    if (l) { gCache[k] = l; gCacheTime[k] = [NSDate date]; } else [gCache removeObjectForKey:k];
    return l;
}
static void forget(NSString *dir) { [gCache removeObjectForKey:dir.lowercaseString]; }

static NSArray<NSDictionary *> *rootsCopy(void) { [gCond lock]; NSArray *d = gRoots ?: @[]; [gCond unlock]; return d; }

static NSDictionary *pcStat(NSString *p) {   // caller holds gCtlLock
    for (NSDictionary *r in rootsCopy()) if ([p isEqualToString:r[@"root"]])
        return @{@"name": r[@"name"], @"dir": @YES, @"size": @0, @"mtime": @0, @"ctime": @0};
    NSString *sep = wireSep(p);
    NSUInteger cut = [p rangeOfString:sep options:NSBackwardsSearch].location;
    NSString *name = cut == NSNotFound ? p : [p substringFromIndex:cut + sep.length];
    BOOL fold = [sep isEqual:@"\\"];
    for (NSDictionary *e in listCached(pcParent(p))) {
        NSString *n = e[@"name"];
        if ((fold ? [n caseInsensitiveCompare:name] : [n compare:name]) == NSOrderedSame) return e;
    }
    return nil;
}

static int pcDelete(NSString *p) {   // caller holds gCtlLock; the PC only removes empty folders, so go bottom-up
    NSDictionary *e = pcStat(p);
    if (!e) return 1;
    int rc;
    if ([e[@"dir"] boolValue]) {
        for (NSDictionary *k in listCached(p) ?: @[]) if ((rc = pcDelete(pcJoin(p, k[@"name"])))) return rc;
        forget(p);
        rc = pcRequest(0x06, p, nil);
    } else rc = pcRequest(0x08, p, nil);
    forget(pcParent(p));
    return rc;
}

// Download: asks for the file and returns 200 once the PC accepts; blocks then arrive in gDlFd. Caller holds gXferLock.
static int pcDownloadBegin(NSString *path, int fd) {
    [gCond lock];
    int status = 503;
    if (gLoggedIn) {
        uint32_t s = newSession();   // session and file ID; the PC echoes both
        gDlFd = fd; gDlSession = s; gDlBytes = 0; gDlDone = gDlFailed = NO; gGot[0x10] = NO;
        sendMsg(msgFiles(0x10, s, s, path), newSession());
        if (waitFor(^{ return (BOOL)(gGot[0x10] || gDlFailed); })) status = gRes[0x10] == 0 && !gDlFailed ? 200 : 404;
        if (status != 200) gDlFd = -1;
    }
    [gCond unlock];
    return status;
}

static void pcDownloadEnd(void) {
    [gCond lock];
    if (gDlFd >= 0 && !gDlDone && gLoggedIn) {   // tell the PC to stop sending
        NSMutableData *m = [NSMutableData data]; w8(m, 0x11); w32(m, gDlSession); w32(m, gDlSession);
        sendMsg(m, newSession());
    }
    gDlFd = -1; gDlSession = 0;
    [gCond unlock];
}

// Upload: 13 pre-check -> A8, then 12 (or 15 for empty) file list, then 0C blocks. Returns an HTTP status.
static int pcUploadLocked(NSString *path, int fd, uint64_t size) {   // caller holds gCond
    if (!gLoggedIn) return 503;
    uint32_t s = newSession(), fid = s;
    gA8 = nil; gWantA8 = YES;
    sendMsg(msgConfirm(s, fid, size, path), newSession());
    BOOL ok = waitFor(^{ return (BOOL)(gA8 != nil); });
    gWantA8 = NO;
    if (!ok) return 503;
    const uint8_t *a = gA8.bytes;
    if (gA8.length < 5) return 502;
    if (a[1] || a[4]) return 403;   // shared read-only / destination read-only
    if (!a[2]) return 507;          // not enough space

    gUlSession = s; gUlFailed = NO;
    sendMsg(msgFiles(size ? 0x12 : 0x15, s, fid, path), newSession());
    uint32_t blocks = (uint32_t)((size + FILE_BLOCK - 1) / FILE_BLOCK);
    for (uint32_t i = 0; i < blocks; i++) {
        if (!waitFor(^{ return (BOOL)(gTx.count < gMaxTx || gUlFailed); }) || gUlFailed) break;
        uint32_t n = (uint32_t)MIN((uint64_t)FILE_BLOCK, size - (uint64_t)i * FILE_BLOCK);
        NSMutableData *b = msgBlock(0x0C, fid, blocks, i + 1, n);
        if (pread(fd, (uint8_t *)b.mutableBytes + 17, n, (off_t)i * FILE_BLOCK) != (ssize_t)n) { gUlFailed = YES; break; }
        sendMsg(b, newSession());
    }
    // The PC only speaks up on failure: wait until everything has left, plus a moment for an A5.
    ok = !gUlFailed && waitFor(^{ return (BOOL)(gTx.count == 0 || gUlFailed); });
    if (ok) [gCond waitUntilDate:[NSDate dateWithTimeIntervalSinceNow:1]];
    BOOL good = ok && !gUlFailed;
    if (!good && gLoggedIn) { NSMutableData *m = [NSMutableData data]; w8(m, 0x14); w32(m, s); sendMsg(m, newSession()); }
    gUlSession = 0;
    return good ? 201 : 502;
}

static int pcCopyFromRemote(NSString *path, NSString *local) {
    int fd = open(local.fileSystemRepresentation, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return 500;
    [gXferLock lock];
    int st = pcDownloadBegin(path, fd);
    if (st == 200) {
        [gCond lock];
        BOOL ok = waitFor(^{ return (BOOL)(gDlDone || gDlFailed); });
        st = ok && !gDlFailed ? 200 : 502;
        [gCond unlock];
    }
    pcDownloadEnd();
    [gXferLock unlock];
    close(fd);
    if (st != 200) unlink(local.fileSystemRepresentation);
    return st;
}
static int pcCopyToRemote(NSString *local, NSString *path) {
    int fd = open(local.fileSystemRepresentation, O_RDONLY);
    if (fd < 0) return 404;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 404; }
    [gXferLock lock]; [gCond lock];
    int rc = pcUploadLocked(path, fd, (uint64_t)st.st_size);
    [gCond unlock]; [gXferLock unlock];
    close(fd);
    return rc;
}

#pragma mark - WebDAV server (what Finder talks to)

@interface Conn : NSObject { @public int fd; NSMutableData *buf; }
@end
@implementation Conn
@end

static BOOL writeAll(int fd, const void *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return NO;
        p = (const uint8_t *)p + w; n -= (size_t)w;
    }
    return YES;
}
static BOOL connFill(Conn *c) {
    uint8_t tmp[65536];
    ssize_t n;
    do n = read(c->fd, tmp, sizeof tmp); while (n < 0 && errno == EINTR);
    if (n <= 0) return NO;
    [c->buf appendBytes:tmp length:(NSUInteger)n];
    return YES;
}
static void connDrop(Conn *c, NSUInteger n) { [c->buf replaceBytesInRange:NSMakeRange(0, n) withBytes:NULL length:0]; }
static NSString *connLine(Conn *c) {
    for (;;) {
        const char *b = c->buf.bytes;
        for (NSUInteger i = 0; i + 1 < c->buf.length; i++)
            if (b[i] == '\r' && b[i + 1] == '\n') {
                NSString *s = [[NSString alloc] initWithBytes:b length:i encoding:NSUTF8StringEncoding] ?: @"";
                connDrop(c, i + 2);
                return s;
            }
        if (c->buf.length > 65536 || !connFill(c)) return nil;
    }
}
static BOOL connBody(Conn *c, uint64_t n, BOOL (^sink)(const void *, size_t)) {
    while (n) {
        if (!c->buf.length && !connFill(c)) return NO;
        size_t k = (size_t)MIN((uint64_t)c->buf.length, n);
        if (!sink(c->buf.bytes, k)) return NO;
        connDrop(c, k); n -= k;
    }
    return YES;
}
static BOOL readBody(Conn *c, NSDictionary *h, BOOL (^sink)(const void *, size_t)) {
    if ([[h[@"transfer-encoding"] lowercaseString] containsString:@"chunked"]) {
        for (;;) {
            NSString *line = connLine(c);
            if (!line) return NO;
            unsigned long long n = strtoull(line.UTF8String, NULL, 16);
            if (!n) { while ((line = connLine(c)) && line.length) {} return line != nil; }   // trailers
            if (!connBody(c, n, sink) || !connLine(c)) return NO;
        }
    }
    return connBody(c, strtoull([h[@"content-length"] ?: @"0" UTF8String], NULL, 10), sink);
}

static NSString *reason(int code) {
    switch (code) {
        case 200: return @"OK"; case 201: return @"Created"; case 204: return @"No Content"; case 207: return @"Multi-Status";
        case 403: return @"Forbidden"; case 404: return @"Not Found"; case 405: return @"Method Not Allowed";
        case 412: return @"Precondition Failed"; case 500: return @"Internal Server Error"; case 502: return @"Bad Gateway";
        case 503: return @"Service Unavailable"; case 507: return @"Insufficient Storage";
    }
    return @"Error";
}
static BOOL sendHead(int fd, int code, NSDictionary *hdr, uint64_t len) {
    NSMutableString *s = [NSMutableString stringWithFormat:@"HTTP/1.1 %d %@\r\nContent-Length: %llu\r\n", code, reason(code), len];
    for (NSString *k in hdr) [s appendFormat:@"%@: %@\r\n", k, hdr[k]];
    if (!hdr[@"DAV"]) [s appendString:@"DAV: 1, 2\r\n"];   // Finder checks this while mounting
    [s appendString:@"\r\n"];
    NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];
    return writeAll(fd, d.bytes, d.length);
}
static BOOL respond(int fd, int code, NSDictionary *hdr, NSData *body) {
    return sendHead(fd, code, hdr, body.length) && (!body.length || writeAll(fd, body.bytes, body.length));
}

static int tempFile(void) {
    char path[PATH_MAX];
    strlcpy(path, [NSTemporaryDirectory() stringByAppendingPathComponent:@"easymaccopy.XXXXXX"].fileSystemRepresentation, sizeof path);
    int fd = mkstemp(path);
    if (fd >= 0) unlink(path);
    return fd;
}

static NSArray<NSDictionary *> *rootsNow(void) { return rootsCopy(); }
static BOOL isVolumeRoot(NSString *p) {
    if (!p.length) return YES;
    for (NSDictionary *r in rootsCopy()) if ([p isEqualToString:r[@"root"]]) return YES;
    return NO;
}

static BOOL wireHasPrefix(NSString *wire, NSString *root) {
    if ([wire isEqualToString:root]) return YES;
    if ([root isEqual:@"/"]) return [wire hasPrefix:@"/"];
    NSString *sep = wireSep(root);
    NSString *pref = [root hasSuffix:sep] ? root : [root stringByAppendingString:sep];
    return [wire hasPrefix:pref];
}
static NSDictionary *bestRoot(NSString *wire, NSArray<NSDictionary *> *roots) {
    NSDictionary *best = nil;
    for (NSDictionary *r in roots) if (wireHasPrefix(wire, r[@"root"]))
        if (!best || [r[@"root"] length] > [best[@"root"] length]) best = r;
    return best;
}

// "/EasySuite/C/a/b" -> "C:\a\b"; "/EasySuite/Macintosh HD/Users" -> "/Volumes/HD/Users".
// Share root -> @"". nil if outside the share, unknown volume, or an unsafe name.
static NSString *pcPathForURLPath(NSString *path, NSArray<NSDictionary *> *roots) {
    NSMutableArray<NSString *> *c = [NSMutableArray array];
    for (NSString *x in [path componentsSeparatedByString:@"/"]) if (x.length) [c addObject:x];
    if (!c.count || ![c[0] isEqual:kShare]) return nil;
    if (c.count == 1) return @"";
    NSDictionary *root = nil;
    for (NSDictionary *r in roots) if ([r[@"id"] isEqual:c[1]]) root = r;
    if (!root) return nil;
    for (NSString *x in c) if ([x isEqual:@".."] || [x containsString:@"\\"]) return nil;
    NSString *base = root[@"root"];
    if (c.count == 2) return base;
    NSString *rel = [[c subarrayWithRange:NSMakeRange(2, c.count - 2)] componentsJoinedByString:wireSep(base)];
    return pcJoin(base, rel);
}

static NSString *hrefRoots(NSString *wire, BOOL dir, NSArray<NSDictionary *> *roots) {
    NSMutableArray<NSString *> *c = [NSMutableArray arrayWithObject:kShare];
    if (wire.length) {
        NSDictionary *r = bestRoot(wire, roots);
        if (!r) return @"/";
        [c addObject:r[@"id"]];
        NSString *rest = wire;
        NSString *base = r[@"root"];
        if ([rest hasPrefix:base]) rest = [rest substringFromIndex:base.length];
        while ([rest hasPrefix:@"/"] || [rest hasPrefix:@"\\"]) rest = [rest substringFromIndex:1];
        for (NSString *x in [rest componentsSeparatedByString:wireSep(base)]) if (x.length) [c addObject:x];
    }
    NSMutableCharacterSet *ok = [NSCharacterSet.URLPathAllowedCharacterSet mutableCopy];
    [ok removeCharactersInString:@"/;&"];
    NSMutableString *s = [NSMutableString string];
    for (NSString *x in c) [s appendFormat:@"/%@", [x stringByAddingPercentEncodingWithAllowedCharacters:ok]];
    if (dir) [s appendString:@"/"];
    return s;
}

static NSString *xmlEsc(NSString *s) {
    return [[[s stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"]
             stringByReplacingOccurrencesOfString:@"<" withString:@"&lt;"] stringByReplacingOccurrencesOfString:@">" withString:@"&gt;"];
}
static NSString *fmtDate(uint64_t t, BOOL http) {
    static const char *wday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char *mon[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    struct tm tm;
    time_t sec = (time_t)t;
    gmtime_r(&sec, &tm);
    char buf[64];
    if (http) snprintf(buf, sizeof buf, "%s, %02d %s %04d %02d:%02d:%02d GMT",
                       wday[tm.tm_wday], tm.tm_mday, mon[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
    else snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return @(buf);
}

static void appendProp(NSMutableString *x, NSString *pc, NSDictionary *e, NSArray<NSDictionary *> *roots) {
    BOOL dir = [e[@"dir"] boolValue];
    [x appendFormat:@"<D:response><D:href>%@</D:href><D:propstat><D:prop><D:displayname>%@</D:displayname>",
        xmlEsc(hrefRoots(pc, dir, roots)), xmlEsc(e[@"name"])];
    if (dir) [x appendString:@"<D:resourcetype><D:collection/></D:resourcetype>"
                              "<D:quota-available-bytes>1099511627776</D:quota-available-bytes><D:quota-used-bytes>0</D:quota-used-bytes>"];
    else [x appendFormat:@"<D:resourcetype/><D:getcontentlength>%llu</D:getcontentlength><D:getcontenttype>application/octet-stream</D:getcontenttype>",
             [e[@"size"] unsignedLongLongValue]];
    [x appendFormat:@"<D:getlastmodified>%@</D:getlastmodified><D:creationdate>%@</D:creationdate>"
                     "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        fmtDate([e[@"mtime"] unsignedLongLongValue], YES), fmtDate([e[@"ctime"] unsignedLongLongValue], NO)];
}

static BOOL doPropfind(int fd, NSString *pc, BOOL children, NSArray *roots) {
    NSMutableString *x = [NSMutableString stringWithString:@"<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">"];
    uint64_t now = (uint64_t)time(NULL);
    if (!pc.length) {
        appendProp(x, @"", @{@"name": kShare, @"dir": @YES, @"mtime": @(now), @"ctime": @(now)}, roots);
        if (children) for (NSDictionary *r in roots)
            appendProp(x, r[@"root"], @{@"name": r[@"name"], @"dir": @YES, @"mtime": @(now), @"ctime": @(now)}, roots);
    } else {
        [gCtlLock lock];
        NSDictionary *e = pcStat(pc);
        NSArray *kids = e && [e[@"dir"] boolValue] && children ? listCached(pc) : nil;
        [gCtlLock unlock];
        if (!e) return respond(fd, 404, nil, nil);
        appendProp(x, pc, e, roots);
        for (NSDictionary *k in kids) appendProp(x, pcJoin(pc, k[@"name"]), k, roots);
    }
    [x appendString:@"</D:multistatus>"];
    return respond(fd, 207, @{@"Content-Type": @"application/xml; charset=utf-8"}, [x dataUsingEncoding:NSUTF8StringEncoding]);
}

static BOOL copyOut(int sock, int f, uint64_t off, uint64_t n) {
    uint8_t buf[65536];
    while (n) {
        ssize_t r = pread(f, buf, (size_t)MIN((uint64_t)sizeof buf, n), (off_t)off);
        if (r <= 0 || !writeAll(sock, buf, (size_t)r)) return NO;
        off += (uint64_t)r; n -= (uint64_t)r;
    }
    return YES;
}

static BOOL doGet(int fd, NSString *pc, BOOL head) {
    if (!pc.length) return respond(fd, 405, nil, nil);
    [gCtlLock lock]; NSDictionary *e = pcStat(pc); [gCtlLock unlock];
    if (!e) return respond(fd, 404, nil, nil);
    if ([e[@"dir"] boolValue]) return respond(fd, 405, nil, nil);
    uint64_t size = [e[@"size"] unsignedLongLongValue];
    NSDictionary *hdr = @{@"Content-Type": @"application/octet-stream", @"Last-Modified": fmtDate([e[@"mtime"] unsignedLongLongValue], YES)};
    if (head || !size) return sendHead(fd, 200, hdr, size);
    int tmp = tempFile();
    if (tmp < 0) return respond(fd, 500, nil, nil);
    [gXferLock lock];
    BOOL keep = NO;
    int st = pcDownloadBegin(pc, tmp);
    if (st != 200) keep = respond(fd, st, nil, nil);
    else if (sendHead(fd, 200, hdr, size)) {
        say(@"← PC  %@", pc);
        // Stream blocks to Finder as they land in the temp file.
        uint64_t sent = 0;
        keep = YES;
        while (keep && sent < size) {
            [gCond lock];
            uint64_t from = sent;
            BOOL alive = waitFor(^{ return (BOOL)(gDlBytes > from || gDlDone || gDlFailed); });
            uint64_t have = MIN(gDlBytes, size);
            BOOL stop = !alive || gDlFailed || (gDlDone && have <= sent);
            [gCond unlock];
            if (have > sent && !copyOut(fd, tmp, sent, have - sent)) keep = NO;
            sent = MAX(sent, have);
            if (stop && sent < size) keep = NO;   // short body: drop the connection so Finder sees an error
        }
        if (keep) { [gCond lock]; waitFor(^{ return (BOOL)(gDlDone || gDlFailed); }); [gCond unlock]; }
    }
    pcDownloadEnd();
    [gXferLock unlock];
    close(tmp);
    return keep;
}

static BOOL handleRequest(Conn *c, NSString *method, NSString *target, NSDictionary *h) {
    int fd = c->fd;
    if ([[h[@"expect"] lowercaseString] isEqual:@"100-continue"]) writeAll(fd, "HTTP/1.1 100 Continue\r\n\r\n", 25);
    NSArray *roots = rootsNow();
    NSString *raw = [target componentsSeparatedByString:@"?"][0];
    if ([raw hasPrefix:@"http://"] || [raw hasPrefix:@"https://"]) raw = [NSURL URLWithString:raw].path ?: @"/";
    NSString *urlPath = raw.stringByRemovingPercentEncoding ?: @"";
    NSString *pc = pcPathForURLPath(urlPath, roots);
    BOOL isPut = [method isEqual:@"PUT"];

    int tmp = isPut ? tempFile() : -1;   // PUT bodies go to a temp file; other bodies aren't needed
    __block uint64_t got = 0;
    if (!readBody(c, h, ^BOOL(const void *b, size_t n) { got += n; return tmp < 0 || writeAll(tmp, b, n); })) {
        if (tmp >= 0) close(tmp);
        return NO;
    }
    BOOL keep;
    if ([method isEqual:@"OPTIONS"])
        keep = respond(fd, 200, @{@"DAV": @"1, 2", @"MS-Author-Via": @"DAV",
                                  @"Allow": @"OPTIONS, PROPFIND, PROPPATCH, GET, HEAD, PUT, DELETE, MKCOL, MOVE, LOCK, UNLOCK"}, nil);
    else if (!pc)
        keep = respond(fd, 404, nil, nil);
    else if ([method isEqual:@"PROPFIND"])
        keep = doPropfind(fd, pc, ![h[@"depth"] isEqual:@"0"], roots);
    else if ([method isEqual:@"GET"] || [method isEqual:@"HEAD"])
        keep = doGet(fd, pc, [method isEqual:@"HEAD"]);
    else if (isPut) {
        int st = 403;
        if (pc.length && !isVolumeRoot(pc) && tmp >= 0) {
            [gXferLock lock]; [gCond lock];
            st = pcUploadLocked(pc, tmp, got);
            [gCond unlock]; [gXferLock unlock];
            [gCtlLock lock]; forget(pcParent(pc)); [gCtlLock unlock];
            say(@"%@  %@ (%llu bytes)", st == 201 ? @"→ PC" : @"→ PC failed", pc, got);
        }
        keep = respond(fd, st, nil, nil);
    } else if ([method isEqual:@"MKCOL"]) {
        int rc = 1;
        if (pc.length && !isVolumeRoot(pc)) { [gCtlLock lock]; rc = pcRequest(0x07, pc, nil); forget(pcParent(pc)); [gCtlLock unlock]; }
        if (rc == 0) say(@"PC new folder %@", pc);
        keep = respond(fd, rc == 0 ? 201 : rc < 0 ? 503 : 405, nil, nil);
    } else if ([method isEqual:@"DELETE"]) {
        int rc = 1;
        if (pc.length && !isVolumeRoot(pc)) { [gCtlLock lock]; rc = pcDelete(pc); [gCtlLock unlock]; }
        if (rc == 0) say(@"PC deleted %@", pc);
        keep = respond(fd, rc == 0 ? 204 : rc < 0 ? 503 : 403, nil, nil);
    } else if ([method isEqual:@"MOVE"]) {
        NSString *dpath = [NSURLComponents componentsWithString:h[@"destination"] ?: @""].percentEncodedPath.stringByRemovingPercentEncoding;
        NSString *dst = dpath ? pcPathForURLPath(dpath, roots) : nil;
        int st = 403;
        if (pc.length && dst.length && !isVolumeRoot(pc) && !isVolumeRoot(dst)) {
            [gCtlLock lock];
            BOOL sameName = [pc caseInsensitiveCompare:dst] == NSOrderedSame;   // case-only rename on Windows
            BOOL exists = !sameName && pcStat(dst) != nil;
            if (exists && [h[@"overwrite"] isEqual:@"F"]) st = 412;
            else {
                if (exists) pcDelete(dst);
                int rc = pcRequest(0x09, pc, dst);
                st = rc == 0 ? (exists ? 204 : 201) : rc < 0 ? 503 : 403;
                if (rc == 0) say(@"PC renamed %@ → %@", pc, dst);
            }
            forget(pcParent(pc)); forget(pcParent(dst)); forget(pc);
            [gCtlLock unlock];
        }
        keep = respond(fd, st, nil, nil);
    } else if ([method isEqual:@"LOCK"]) {         // Finder needs locking to mount read-write; there's one user, so grant all
        NSString *tok = [NSString stringWithFormat:@"opaquelocktoken:%@", NSUUID.UUID.UUIDString];
        NSString *x = [NSString stringWithFormat:@"<?xml version=\"1.0\" encoding=\"utf-8\"?><D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                       "<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>0</D:depth>"
                       "<D:timeout>Second-3600</D:timeout><D:locktoken><D:href>%@</D:href></D:locktoken></D:activelock></D:lockdiscovery></D:prop>", tok];
        keep = respond(fd, 200, @{@"Lock-Token": [NSString stringWithFormat:@"<%@>", tok], @"Content-Type": @"application/xml; charset=utf-8"},
                       [x dataUsingEncoding:NSUTF8StringEncoding]);
    } else if ([method isEqual:@"UNLOCK"])
        keep = respond(fd, 204, nil, nil);
    else if ([method isEqual:@"PROPPATCH"]) {      // accept and ignore (Windows has no place for these)
        NSString *x = [NSString stringWithFormat:@"<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\"><D:response>"
                       "<D:href>%@</D:href><D:propstat><D:prop/><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>",
                       xmlEsc(target)];
        keep = respond(fd, 207, @{@"Content-Type": @"application/xml; charset=utf-8"}, [x dataUsingEncoding:NSUTF8StringEncoding]);
    } else
        keep = respond(fd, 405, nil, nil);
    if (tmp >= 0) close(tmp);
    return keep;
}

static void serveConn(int fd) {
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    Conn *c = [Conn new]; c->fd = fd; c->buf = [NSMutableData data];
    for (BOOL keep = YES; keep; ) {
        @autoreleasepool {
            NSString *line = connLine(c);
            if (!line) break;
            if (!line.length) continue;
            NSArray<NSString *> *p = [line componentsSeparatedByString:@" "];
            if (p.count < 3) break;
            NSMutableDictionary *h = [NSMutableDictionary dictionary];
            NSString *l;
            while ((l = connLine(c)) && l.length) {
                NSRange r = [l rangeOfString:@":"];
                if (r.location != NSNotFound)
                    h[[l substringToIndex:r.location].lowercaseString] = [[l substringFromIndex:r.location + 1] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
            }
            if (!l) break;
            keep = handleRequest(c, p[0], p[1], h) && ![[h[@"connection"] lowercaseString] isEqual:@"close"];
        }
    }
    close(fd);
}

static BOOL startWebDAV(void) {   // loopback only: nothing off this Mac can reach it
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a = {.sin_len = sizeof a, .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof a;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 32) || getsockname(s, (struct sockaddr *)&a, &len)) {
        say(@"Couldn't start the Finder bridge (%s).", strerror(errno));
        return NO;
    }
    gHttpPort = ntohs(a.sin_port);
    [NSThread detachNewThreadWithBlock:^{
        for (;;) {
            int c = accept(s, NULL, NULL);
            if (c >= 0) [NSThread detachNewThreadWithBlock:^{ serveConn(c); }];
        }
    }];
    return YES;
}

#pragma mark - file window

static NSString *fmtBytes(uint64_t n) {
    if (n < 1024) return [NSString stringWithFormat:@"%llu bytes", n];
    if (n < 1024 * 1024) return [NSString stringWithFormat:@"%.1f KB", n / 1024.0];
    if (n < 1024ull * 1024 * 1024) return [NSString stringWithFormat:@"%.1f MB", n / (1024.0 * 1024)];
    return [NSString stringWithFormat:@"%.2f GB", n / (1024.0 * 1024 * 1024)];
}
static NSString *fmtWhen(uint64_t unixSecs) {
    if (!unixSecs) return @"";
    static NSDateFormatter *fmt;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fmt = [NSDateFormatter new];
        fmt.dateFormat = @"yyyy-MM-dd HH:mm";
    });
    return [fmt stringFromDate:[NSDate dateWithTimeIntervalSince1970:unixSecs]];
}

@interface Browser : NSObject <NSApplicationDelegate, NSWindowDelegate, NSTableViewDataSource, NSTableViewDelegate>
@property (nonatomic, strong) NSWindow *window;
@property (nonatomic, strong) NSTableView *table;
@property (nonatomic, strong) NSTextField *pathLabel;
@property (nonatomic, strong) NSTextField *status;
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *rows;
@property (nonatomic, copy) NSString *wire;
@property (nonatomic) BOOL busy;
@end

@implementation Browser
- (NSString *)statusText {
    [gCond lock];
    BOOL in = gLoggedIn; unsigned os = gRemoteOS; NSString *mp = gMountPoint;
    [gCond unlock];
    if (!in) return @"Waiting for the other computer…";
    NSString *who = os == 0x14 ? @"Linux" : (os >= 8 ? @"Mac" : @"Windows");
    return mp ? [NSString stringWithFormat:@"Connected to %@. In Finder at %@", who, mp]
              : [NSString stringWithFormat:@"Connected to %@.", who];
}
- (void)refreshStatus { if (!self.busy) self.status.stringValue = [self statusText]; }
- (void)reload {
    if (self.busy) return;
    self.busy = YES; self.status.stringValue = @"Working…";
    NSString *path = self.wire ?: @"";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableArray *rows = [NSMutableArray array];
        if (!path.length) {
            for (NSDictionary *r in rootsNow())
                [rows addObject:@{@"name": r[@"name"], @"wire": r[@"root"], @"dir": @YES, @"size": @0, @"mtime": @0}];
        } else {
            [gCtlLock lock]; NSArray *list = listCached(path); [gCtlLock unlock];
            for (NSDictionary *e in list)
                [rows addObject:@{@"name": e[@"name"], @"wire": pcJoin(path, e[@"name"]), @"dir": e[@"dir"], @"size": e[@"size"] ?: @0, @"mtime": e[@"mtime"] ?: @0}];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self.rows = rows; self.busy = NO;
            self.pathLabel.stringValue = path.length ? path : @"EasySuite";
            [self.table reloadData];
            [self refreshStatus];
        });
    });
}
- (BOOL)wireIsRoot:(NSString *)p {
    for (NSDictionary *r in rootsNow()) if ([p isEqualToString:r[@"root"]]) return YES;
    return NO;
}
- (void)up:(id)sender {
    (void)sender; if (self.busy || !self.wire.length) return;
    if ([self wireIsRoot:self.wire]) self.wire = @"";
    else self.wire = pcParent(self.wire);
    [self reload];
}
- (void)refresh:(id)sender { (void)sender; if (self.wire.length) forget(self.wire); [self reload]; }
- (NSString *)ask:(NSString *)title initial:(NSString *)initial {
    NSAlert *a = [NSAlert new]; a.messageText = title;
    NSTextField *f = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 24)];
    f.stringValue = initial ?: @""; a.accessoryView = f;
    [a addButtonWithTitle:@"OK"]; [a addButtonWithTitle:@"Cancel"];
    [a layout]; [a.window makeFirstResponder:f];
    if ([a runModal] != NSAlertFirstButtonReturn) return nil;
    NSString *s = [f.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    return s.length ? s : nil;
}
- (void)mkdir:(id)sender {
    (void)sender; if (self.busy || !self.wire.length) return;
    NSString *name = [self ask:@"New folder" initial:@""]; if (!name) return;
    NSString *path = pcJoin(self.wire, name); NSString *parent = self.wire;
    self.busy = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int rc = pcRequest(0x07, path, nil); forget(parent);
        dispatch_async(dispatch_get_main_queue(), ^{ self.busy = NO; self.status.stringValue = rc == 0 ? @"Folder created." : @"Couldn't create the folder."; [self reload]; });
    });
}
- (void)delete:(id)sender {
    (void)sender; NSInteger row = self.table.selectedRow; if (row < 0 || self.busy || !self.wire.length) return;
    NSDictionary *e = self.rows[row];
    NSAlert *a = [NSAlert new]; a.messageText = [NSString stringWithFormat:@"Delete \"%@\"?", e[@"name"]];
    [a addButtonWithTitle:@"Delete"]; [a addButtonWithTitle:@"Cancel"];
    if ([a runModal] != NSAlertFirstButtonReturn) return;
    NSString *path = e[@"wire"]; NSString *parent = self.wire;
    self.busy = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [gCtlLock lock]; int rc = pcDelete(path); [gCtlLock unlock]; forget(parent);
        dispatch_async(dispatch_get_main_queue(), ^{ self.busy = NO; self.status.stringValue = rc == 0 ? @"Deleted." : @"Couldn't delete that."; [self reload]; });
    });
}
- (void)rename:(id)sender {
    (void)sender; NSInteger row = self.table.selectedRow; if (row < 0 || self.busy || !self.wire.length) return;
    NSDictionary *e = self.rows[row];
    NSString *name = [self ask:@"Rename" initial:e[@"name"]]; if (!name) return;
    NSString *dest = pcJoin(self.wire, name); NSString *parent = self.wire; NSString *from = e[@"wire"];
    self.busy = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int rc = pcRequest(0x09, from, dest); forget(parent);
        dispatch_async(dispatch_get_main_queue(), ^{ self.busy = NO; self.status.stringValue = rc == 0 ? @"Renamed." : @"Couldn't rename that."; [self reload]; });
    });
}
- (void)download:(id)sender {
    (void)sender; NSInteger row = self.table.selectedRow; if (row < 0 || self.busy) return;
    NSDictionary *e = self.rows[row]; if ([e[@"dir"] boolValue]) return;
    NSSavePanel *p = [NSSavePanel savePanel]; p.nameFieldStringValue = e[@"name"];
    if ([p runModal] != NSModalResponseOK) return;
    NSString *dest = p.URL.path; NSString *wire = e[@"wire"];
    self.busy = YES; self.status.stringValue = @"Downloading…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int rc = pcCopyFromRemote(wire, dest);
        dispatch_async(dispatch_get_main_queue(), ^{ self.busy = NO; self.status.stringValue = rc == 200 ? @"Downloaded." : @"Download failed."; });
    });
}
- (void)upload:(id)sender {
    (void)sender; if (self.busy || !self.wire.length) return;
    NSOpenPanel *p = [NSOpenPanel openPanel]; p.canChooseFiles = YES; p.canChooseDirectories = NO;
    if ([p runModal] != NSModalResponseOK) return;
    NSString *local = p.URL.path; NSString *dest = pcJoin(self.wire, local.lastPathComponent); NSString *parent = self.wire;
    self.busy = YES; self.status.stringValue = @"Uploading…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int rc = pcCopyToRemote(local, dest); forget(parent);
        dispatch_async(dispatch_get_main_queue(), ^{ self.busy = NO; self.status.stringValue = rc == 201 ? @"Uploaded." : @"Upload failed."; [self reload]; });
    });
}
- (void)doubleClick:(id)sender {
    (void)sender; NSInteger row = self.table.clickedRow; if (row < 0 || row >= (NSInteger)self.rows.count) return;
    NSDictionary *e = self.rows[row];
    if ([e[@"dir"] boolValue]) { self.wire = e[@"wire"]; [self reload]; }
    else [self download:nil];
}
- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView { (void)tableView; return (NSInteger)self.rows.count; }
- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)col row:(NSInteger)row {
    (void)tableView; NSDictionary *e = self.rows[row]; NSString *ident = col.identifier;
    if ([ident isEqual:@"size"]) return [e[@"dir"] boolValue] ? @"" : fmtBytes([e[@"size"] unsignedLongLongValue]);
    if ([ident isEqual:@"date"]) return fmtWhen([e[@"mtime"] unsignedLongLongValue]);
    if ([ident isEqual:@"kind"]) return [e[@"dir"] boolValue] ? @"Folder" : @"File";
    return e[@"name"];
}
- (void)show {
    self.rows = [NSMutableArray array]; self.wire = @"";
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 960, 600)
                                               styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                                                 backing:NSBackingStoreBuffered defer:NO];
    self.window.title = @"EasySuite"; self.window.delegate = self; [self.window center];
    NSView *cv = self.window.contentView;
    NSArray *titles = @[@"Up", @"Refresh", @"New Folder", @"Delete", @"Rename", @"Download", @"Upload"];
    NSArray *sels = @[@"up:", @"refresh:", @"mkdir:", @"delete:", @"rename:", @"download:", @"upload:"];
    CGFloat x = 12;
    for (NSUInteger i = 0; i < titles.count; i++) {
        NSButton *b = [NSButton buttonWithTitle:titles[i] target:self action:NSSelectorFromString(sels[i])];
        b.translatesAutoresizingMaskIntoConstraints = YES;
        b.frame = NSMakeRect(x, NSHeight(cv.bounds) - 40, 110, 28);
        b.autoresizingMask = NSViewMinYMargin;
        [cv addSubview:b]; x += 116;
    }
    self.pathLabel = [NSTextField labelWithString:@"EasySuite"];
    self.pathLabel.translatesAutoresizingMaskIntoConstraints = YES;
    self.pathLabel.frame = NSMakeRect(12, NSHeight(cv.bounds) - 64, NSWidth(cv.bounds) - 24, 18);
    self.pathLabel.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    [cv addSubview:self.pathLabel];
    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 28, NSWidth(cv.bounds), NSHeight(cv.bounds) - 96)];
    scroll.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    scroll.hasVerticalScroller = YES; scroll.borderType = NSBezelBorder;
    self.table = [[NSTableView alloc] initWithFrame:scroll.bounds];
    self.table.usesAlternatingRowBackgroundColors = YES;
    self.table.doubleAction = @selector(doubleClick:); self.table.target = self;
    self.table.dataSource = self; self.table.delegate = self;
    for (NSArray *col in @[@[@"name", @"Name", @340], @[@"size", @"Size", @110], @[@"date", @"Modified", @160], @[@"kind", @"Kind", @90]]) {
        NSTableColumn *c = [[NSTableColumn alloc] initWithIdentifier:col[0]];
        c.title = col[1]; c.width = [col[2] doubleValue];
        [self.table addTableColumn:c];
    }
    scroll.documentView = self.table; [cv addSubview:scroll];
    self.status = [NSTextField labelWithString:@"Waiting for the other computer…"];
    self.status.translatesAutoresizingMaskIntoConstraints = YES;
    self.status.frame = NSMakeRect(12, 6, NSWidth(cv.bounds) - 24, 18);
    self.status.autoresizingMask = NSViewWidthSizable | NSViewMaxYMargin;
    [cv addSubview:self.status];
    [NSTimer scheduledTimerWithTimeInterval:0.8 repeats:YES block:^(NSTimer *t) {
        (void)t; if (!self.busy && !self.wire.length) {
            static NSUInteger last = 0; NSUInteger n = rootsNow().count;
            BOOL in = NO; [gCond lock]; in = gLoggedIn; [gCond unlock];
            if ((in ? n + 1 : 0) != last) { last = in ? n + 1 : 0; [self reload]; }
            else [self refreshStatus];
        } else [self refreshStatus];
    }];
    [self.window makeKeyAndOrderFront:nil];
    [self reload];
}
- (void)windowWillClose:(NSNotification *)note { (void)note; gStop = 1; }
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
    (void)sender; gStop = 1;
    if (gServeDone) return NSTerminateNow;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        for (int i = 0; i < 40 && !gServeDone; i++) usleep(100000);
        dispatch_async(dispatch_get_main_queue(), ^{ [NSApp replyToApplicationShouldTerminate:YES]; });
    });
    return NSTerminateLater;
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender { (void)sender; return NO; }
@end

static Browser *gBrowser;

#pragma mark - run / install

static void runForever(void) {
    startWebDAV();
    BOOL told = NO;
    while (!gStop) {
        io_service_t svc = findCable();
        if (!svc) {
            if (!told) { say(@"Waiting for the EasySuite cable to be plugged in…"); told = YES; }
            sleep(2);
            continue;
        }
        IOObjectRelease(svc);
        told = NO;
        if (!openCable()) { sleep(5); continue; }
        uint8_t ver[12] = {0}, bus[2] = {0};
        otiCmd(0xF0, 0, 0, 0, 0, ver, sizeof ver, IN);
        otiCmd(0xD8, 0, 2, 0, 0, bus, sizeof bus, IN);
        otiCmd(0xD8, 1, 5, 0, 0x7F, NULL, 0, NONE);              // packet size register, as the original
        say(@"Cable ready (firmware %.6s, USB %@).", (const char *)ver + 6, bus[0] == 0x20 ? @"2.0" : bus[0] == 0x11 ? @"1.1" : @"?");
        [gCond lock]; gBus = bus[0] << 8 | bus[1]; gBooking = 15; gMaxTx = 45; [gCond unlock];
        serveCable();
        [gCond lock];
        remoteGone();
        gConnGen++;
        NSString *mp = takeMountPoint();
        [gCond broadcast];
        [gCond unlock];
        unmountPath(mp);
        closeCable();
    }
    gServeDone = 1;
}

static int runTool(NSString *tool, NSArray *args) {
    NSTask *t = [NSTask launchedTaskWithExecutableURL:[NSURL fileURLWithPath:tool] arguments:args error:nil terminationHandler:nil];
    [t waitUntilExit];
    return t ? t.terminationStatus : -1;
}

// LaunchAgent that keeps `serve` running, so plugging the cable in is all it takes.
static int install(BOOL remove) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *home = NSHomeDirectory();
    NSString *dir = [home stringByAppendingPathComponent:@"Library/Application Support/EasyMacCopy"];
    NSString *bin = [dir stringByAppendingPathComponent:@"easymaccopy"];   // launchd can't run binaries from ~/Desktop or ~/Documents
    NSString *plist = [home stringByAppendingFormat:@"/Library/LaunchAgents/%@.plist", kLabel];
    NSString *domain = [NSString stringWithFormat:@"gui/%u", getuid()];
    runTool(@"/bin/launchctl", @[@"bootout", [NSString stringWithFormat:@"%@/%@", domain, kLabel]]);   // fine if not loaded
    if (remove) {
        [fm removeItemAtPath:plist error:nil];
        [fm removeItemAtPath:dir error:nil];
        say(@"Uninstalled.");
        return 0;
    }
    NSError *err = nil;
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:plist.stringByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:nil];
    [fm removeItemAtPath:bin error:nil];
    NSDictionary *job = @{@"Label": kLabel, @"ProgramArguments": @[bin, @"serve"], @"RunAtLoad": @YES, @"KeepAlive": @YES,
                          @"ThrottleInterval": @10, @"ProcessType": @"Interactive",
                          @"StandardErrorPath": [home stringByAppendingPathComponent:@"Library/Logs/easymaccopy.log"]};
    if (![fm copyItemAtPath:NSBundle.mainBundle.executablePath toPath:bin error:&err] ||
        ![job writeToURL:[NSURL fileURLWithPath:plist] error:&err]) { say(@"Install failed: %@", err.localizedDescription); return 1; }
    if (runTool(@"/bin/launchctl", @[@"bootstrap", domain, plist])) { say(@"launchctl couldn't load %@", plist); return 1; }
    say(@"Installed. Plug in the cable and open EasySuite on the other computer; it appears in Finder as \"%@\".\nLog: ~/Library/Logs/easymaccopy.log", kShare);
    return 0;
}

#pragma mark - self-test (no hardware)

static int selftest(void) {
    [gCond lock];
    // 1. packetize + reassemble a multi-packet message
    NSMutableData *big = [NSMutableData dataWithLength:150000];
    arc4random_buf(big.mutableBytes, big.length);
    sendMsg(big, 77);
    NSCAssert(gTx.count == 3, @"150000 bytes -> 3 packets");
    NSData *got = nil; uint32_t s = 0;
    for (NSData *p in gTx) got = reassemble(p.bytes, &s) ?: got;
    NSCAssert([got isEqual:big] && s == 77, @"reassembly");
    [gTx removeAllObjects];

    // 2. PC (little-endian) download request -> A1, A3 blocks, A7, data intact
    NSString *dir = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
    [NSFileManager.defaultManager createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *src = [dir stringByAppendingPathComponent:@"src.bin"];
    NSMutableData *content = [NSMutableData dataWithLength:FILE_BLOCK + 12345];
    arc4random_buf(content.mutableBytes, content.length);
    [content writeToFile:src atomically:NO];
    NSData *p16 = [src dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
    NSMutableData *req = [NSMutableData data];
    uint8_t cmd = 0x10; [req appendBytes:&cmd length:1];
    uint32_t le32 = OSSwapHostToLittleInt32(42); [req appendBytes:&le32 length:4];
    uint16_t le16 = OSSwapHostToLittleInt16(1); [req appendBytes:&le16 length:2];
    le32 = OSSwapHostToLittleInt32(9); [req appendBytes:&le32 length:4];
    le16 = OSSwapHostToLittleInt16((uint16_t)p16.length); [req appendBytes:&le16 length:2];
    [req appendData:p16];
    gRemoteLE = YES; gMaxTx = 1000;
    dispatch(req, 1);
    pumpDownloads();
    NSMutableArray<NSData *> *msgs = [NSMutableArray array];
    for (NSData *p in gTx) { NSData *m = reassemble(p.bytes, &s); if (m) [msgs addObject:m]; }
    [gTx removeAllObjects];
    NSCAssert(msgs.count == 4, @"A1 + 2x A3 + A7");
    const uint8_t *a1 = msgs[0].bytes, *a7 = msgs[3].bytes;
    NSCAssert(a1[0] == 0xA1 && a1[1] == 0x10 && a1[2] == 0, @"A1 ok");
    NSMutableData *back = [NSMutableData data];
    for (int i = 1; i <= 2; i++) {
        const uint8_t *b = msgs[i].bytes;
        NSCAssert(b[0] == 0xA3 && OSReadBigInt32(b, 1) == 9 && OSReadBigInt32(b, 5) == 2 && OSReadBigInt32(b, 9) == (uint32_t)i, @"A3 header");
        [back appendBytes:b + 17 length:OSReadBigInt32(b, 13)];
    }
    NSCAssert([back isEqual:content], @"download data");
    NSCAssert(a7[0] == 0xA7 && OSReadBigInt32(a7, 1) == 42, @"A7 finish");

    // 3. PC upload: 0x12 file list, then two 0x0C blocks -> file written
    NSString *dst = [dir stringByAppendingPathComponent:@"dst.bin"];
    NSData *d16 = [dst dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
    req = [NSMutableData data];
    cmd = 0x12; [req appendBytes:&cmd length:1];
    le32 = OSSwapHostToLittleInt32(43); [req appendBytes:&le32 length:4];
    le16 = OSSwapHostToLittleInt16(1); [req appendBytes:&le16 length:2];
    le32 = OSSwapHostToLittleInt32(5); [req appendBytes:&le32 length:4];
    le16 = OSSwapHostToLittleInt16((uint16_t)d16.length); [req appendBytes:&le16 length:2];
    [req appendData:d16];
    dispatch(req, 2);
    for (uint32_t i = 1; i <= 2; i++) {
        uint32_t off = (i - 1) * FILE_BLOCK, n = i == 1 ? FILE_BLOCK : 12345;
        req = [NSMutableData data];
        cmd = 0x0C; [req appendBytes:&cmd length:1];
        uint32_t f[4] = {OSSwapHostToLittleInt32(5), OSSwapHostToLittleInt32(2), OSSwapHostToLittleInt32(i), OSSwapHostToLittleInt32(n)};
        [req appendBytes:f length:16];
        [req appendBytes:(const uint8_t *)content.bytes + off length:n];
        dispatch(req, 3);
    }
    NSCAssert([[NSData dataWithContentsOfFile:dst] isEqual:content] && gUpFd < 0, @"upload data");

    // 4. directory listing entry is 552 bytes, big-endian size field
    NSMutableData *e = [NSMutableData data];
    NSCAssert(appendDirEntry(e, dir, @"src.bin") && e.length == 0x228, @"entry size");
    NSCAssert(OSReadBigInt64(e.bytes, 0x1C) == content.length && OSReadBigInt32(e.bytes, 0x24) == 14, @"entry fields");

    // 5. truncated request is ignored, not read past the end
    uint8_t bad[] = {0x10, 1, 0, 0, 0, 5, 0};   // claims 5 files, carries none
    dispatch([NSData dataWithBytes:bad length:sizeof bad], 4);
    NSCAssert(gTx.count == 0, @"bad request ignored");

    // 6. client side: a PC's (little-endian) listing parses
    NSMutableData *a2 = [NSMutableData dataWithLength:3 + 2 * 0x228];
    uint8_t *q = a2.mutableBytes; q[0] = 0xA2; OSWriteLittleInt16(q, 1, 2);
    NSArray *names = @[@"Docs", @"a.txt"];
    for (int i = 0; i < 2; i++) {
        uint8_t *ent = q + 3 + i * 0x228;
        NSData *n16 = [names[i] dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        OSWriteLittleInt32(ent, 0, i ? 0x20 : 0x10); OSWriteLittleInt64(ent, 0x14, 1700000000); OSWriteLittleInt64(ent, 0x1C, i ? 5 : 0);
        OSWriteLittleInt32(ent, 0x24, (uint32_t)n16.length); memcpy(ent + 0x28, n16.bytes, n16.length);
    }
    NSArray<NSDictionary *> *list = parseDirReply(a2);
    NSCAssert(list.count == 2 && [list[0][@"name"] isEqual:@"Docs"] && [list[0][@"dir"] boolValue] && ![list[1][@"dir"] boolValue]
              && [list[1][@"size"] isEqual:@5] && [list[1][@"mtime"] isEqual:@1700000000], @"PC listing");

    // 7. client side: download blocks land in the sink, A7 finishes it
    int sink = tempFile();
    gDlFd = sink; gDlSession = 99; gDlBytes = 0; gDlDone = gDlFailed = NO;
    uint8_t a3[17 + 4] = {0xA3}; OSWriteLittleInt32(a3, 1, 99); OSWriteLittleInt32(a3, 5, 1); OSWriteLittleInt32(a3, 9, 1); OSWriteLittleInt32(a3, 13, 4);
    memcpy(a3 + 17, "data", 4);
    dispatch([NSData dataWithBytes:a3 length:sizeof a3], 5);
    uint8_t fin[5] = {0xA7}; OSWriteLittleInt32(fin, 1, 99);
    dispatch([NSData dataWithBytes:fin length:sizeof fin], 6);
    char chk[4] = {0};
    NSCAssert(gDlBytes == 4 && gDlDone && pread(sink, chk, 4, 0) == 4 && !memcmp(chk, "data", 4), @"download sink");
    close(sink); gDlFd = -1;

    // 8. URL <-> wire path, for a Windows peer and a Mac peer
    NSArray *dr = @[@{@"id": @"C", @"name": @"C", @"root": @"C:\\"}, @{@"id": @"D", @"name": @"D", @"root": @"D:\\"}];
    NSCAssert([pcPathForURLPath(@"/EasySuite/C/Users/a b", dr) isEqual:@"C:\\Users\\a b"], @"map file");
    NSCAssert([pcPathForURLPath(@"/EasySuite/D/", dr) isEqual:@"D:\\"] && [pcPathForURLPath(@"/EasySuite", dr) isEqual:@""], @"map roots");
    NSCAssert(!pcPathForURLPath(@"/EasySuite/Q/x", dr) && !pcPathForURLPath(@"/EasySuite/C/../x", dr) && !pcPathForURLPath(@"/other", dr), @"map rejects");
    NSCAssert([hrefRoots(@"C:\\a b&c", NO, dr) isEqual:@"/EasySuite/C/a%20b%26c"] && [pcParent(@"C:\\a") isEqual:@"C:\\"], @"href");
    NSArray *macRoots = @[@{@"id": @"HD", @"name": @"HD", @"root": @"/Volumes/HD"}];
    NSCAssert([pcPathForURLPath(@"/EasySuite/HD/Users/a", macRoots) isEqual:@"/Volumes/HD/Users/a"], @"mac map");
    NSCAssert([pcParent(@"/Volumes/HD/Users") isEqual:@"/Volumes/HD"] && [pcJoin(@"/", @"Users") isEqual:@"/Users"], @"posix paths");

    // 8a. volume lists from a Mac (big-endian names) and from Windows (drive letters)
    NSMutableData *a4 = [NSMutableData data];
    uint8_t a4cmd = 0xA4; [a4 appendBytes:&a4cmd length:1];
    uint16_t one = OSSwapHostToLittleInt16(1); [a4 appendBytes:&one length:2];
    uint8_t pair[2] = {'A', 0x12}; [a4 appendBytes:pair length:2];
    NSData *hn = [@"HD" dataUsingEncoding:NSUTF16BigEndianStringEncoding];
    NSData *hp = [@"/Volumes/HD" dataUsingEncoding:NSUTF16BigEndianStringEncoding];
    uint16_t hnl = OSSwapHostToBigInt16((uint16_t)hn.length), hpl = OSSwapHostToBigInt16((uint16_t)hp.length);
    [a4 appendBytes:&hnl length:2]; [a4 appendData:hn]; [a4 appendBytes:&hpl length:2]; [a4 appendData:hp];
    gRemoteOS = 0x13; gRemoteLE = NO;
    dispatch(a4, 9);
    NSCAssert(gRoots.count == 1 && [gRoots[0][@"root"] isEqual:@"/Volumes/HD"] && [gRoots[0][@"id"] isEqual:@"HD"], @"mac volumes");
    uint8_t pca4[] = {0xA4, 3, 0, 'A', 0x11, 'C', 0x12, 'D', 0x12};
    gRemoteOS = 5; gRemoteLE = YES;
    dispatch([NSData dataWithBytes:pca4 length:sizeof pca4], 10);
    NSCAssert(gRoots.count == 2 && [gRoots[0][@"root"] isEqual:@"C:\\"] && [gRoots[1][@"id"] isEqual:@"D"], @"windows volumes");

    // 8b. Mac-as-client request bytes match the PowerPC builders (big-endian, UTF-16BE, no BOM)
    NSData *cu = [@"C:\\" dataUsingEncoding:NSUTF16BigEndianStringEncoding];
    NSData *listMsg = msgList(@"C:\\");
    const uint8_t *lb = listMsg.bytes;
    NSCAssert(lb[0] == 0x04 && OSReadBigInt16(lb, 1) == cu.length && listMsg.length == 3 + cu.length
              && !memcmp(lb + 3, cu.bytes, cu.length), @"list request");
    NSData *made = [@"C:\\New" dataUsingEncoding:NSUTF16BigEndianStringEncoding];
    NSData *mk = msgPaths(0x07, 0x11223344, @"C:\\New", nil);
    lb = mk.bytes;
    NSCAssert(mk.length == 7 + made.length && lb[0] == 0x07 && OSReadBigInt32(lb, 1) == 0x11223344
              && OSReadBigInt16(lb, 5) == made.length && !memcmp(lb + 7, made.bytes, made.length), @"mkdir request");
    NSData *oa = [@"C:\\a" dataUsingEncoding:NSUTF16BigEndianStringEncoding];
    NSData *ob = [@"C:\\b" dataUsingEncoding:NSUTF16BigEndianStringEncoding];
    NSData *mv = msgPaths(0x09, 7, @"C:\\a", @"C:\\b");
    lb = mv.bytes;
    NSCAssert(lb[0] == 0x09 && OSReadBigInt16(lb, 5) == oa.length && OSReadBigInt16(lb, 7) == ob.length
              && !memcmp(lb + 9, oa.bytes, oa.length) && !memcmp(lb + 9 + oa.length, ob.bytes, ob.length), @"rename request");
    NSData *del = msgPaths(0x08, 1, @"C:\\a", nil);
    NSCAssert(((const uint8_t *)del.bytes)[0] == 0x08 && msgPaths(0x06, 1, @"C:\\a", nil).length == del.length, @"delete requests");
    NSData *ap = [@"C:\\a.txt" dataUsingEncoding:NSUTF16BigEndianStringEncoding];
    NSData *dl = msgFiles(0x10, 42, 9, @"C:\\a.txt");
    lb = dl.bytes;
    NSCAssert(lb[0] == 0x10 && OSReadBigInt32(lb, 1) == 42 && OSReadBigInt16(lb, 5) == 1 && OSReadBigInt32(lb, 7) == 9
              && OSReadBigInt16(lb, 11) == ap.length && !memcmp(lb + 13, ap.bytes, ap.length), @"download request");
    NSData *cf = msgConfirm(3, 9, 100, @"C:\\a.txt");
    lb = cf.bytes;
    NSCAssert(lb[0] == 0x13 && OSReadBigInt32(lb, 1) == 3 && OSReadBigInt64(lb, 5) == 100 && OSReadBigInt16(lb, 13) == 0
              && OSReadBigInt16(lb, 15) == 1 && OSReadBigInt32(lb, 17) == 9, @"upload confirm");
    NSCAssert(((const uint8_t *)msgFiles(0x12, 3, 9, @"C:\\a.txt").bytes)[0] == 0x12
              && ((const uint8_t *)msgFiles(0x15, 3, 9, @"C:\\a.txt").bytes)[0] == 0x15, @"upload lists");
    uint8_t payload[4] = {1, 2, 3, 4};
    NSMutableData *blk = msgBlock(0x0C, 9, 2, 1, 4);
    memcpy((uint8_t *)blk.mutableBytes + 17, payload, 4);
    lb = blk.bytes;
    NSCAssert(lb[0] == 0x0C && OSReadBigInt32(lb, 1) == 9 && OSReadBigInt32(lb, 5) == 2 && OSReadBigInt32(lb, 9) == 1
              && OSReadBigInt32(lb, 13) == 4 && !memcmp(lb + 17, payload, 4), @"upload block");
    gRoots = dr;
    [gCond unlock];

    // 9. the WebDAV server answers Finder-style requests at the share root (no PC needed there)
    if (startWebDAV()) {
        NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d/EasySuite/", gHttpPort]]];
        rq.HTTPMethod = @"PROPFIND"; [rq setValue:@"1" forHTTPHeaderField:@"Depth"];
        __block NSInteger code = 0; __block NSString *body = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[NSURLSession.sharedSession dataTaskWithRequest:rq completionHandler:^(NSData *d, NSURLResponse *r, NSError *err) {
            code = [(NSHTTPURLResponse *)r statusCode]; body = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : err.description;
            dispatch_semaphore_signal(sem);
        }] resume];
        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
        NSCAssert(code == 207 && [body containsString:@"<D:href>/EasySuite/D/</D:href>"], @"PROPFIND root: %ld %@", (long)code, body);
    }

    [NSFileManager.defaultManager removeItemAtPath:dir error:nil];
    say(@"selftest: OK");
    return 0;
}

#pragma mark - main

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        gCond = [NSCondition new]; gCtlLock = [NSLock new]; gXferLock = [NSLock new];
        gTx = [NSMutableArray array]; gJobs = [NSMutableArray array];
        gRxBuf = [NSMutableDictionary dictionary]; gRxCount = [NSMutableDictionary dictionary];
        gCache = [NSMutableDictionary dictionary]; gCacheTime = [NSMutableDictionary dictionary];
        gActivity = [NSDate date];
        gSessionCtr = arc4random() & 0x7FFFFFFF;
        NSString *mode = argc > 1 ? @(argv[1]) : @"serve";
        if ([mode isEqual:@"selftest"]) return selftest();
        if ([mode isEqual:@"install"]) return install(NO);
        if ([mode isEqual:@"uninstall"]) return install(YES);
        if ([mode isEqual:@"serve"]) {
            signal(SIGINT, onSignal); signal(SIGTERM, onSignal);
            [NSApplication sharedApplication];
            [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
            NSMenu *bar = [NSMenu new]; NSMenuItem *appItem = [NSMenuItem new]; [bar addItem:appItem];
            NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"EasySuite"];
            [appMenu addItemWithTitle:@"Quit EasySuite" action:@selector(terminate:) keyEquivalent:@"q"];
            appItem.submenu = appMenu; NSApp.mainMenu = bar;
            gBrowser = [Browser new]; NSApp.delegate = gBrowser; [gBrowser show];
            [NSThread detachNewThreadWithBlock:^{
                runForever();
                dispatch_async(dispatch_get_main_queue(), ^{ [NSApp terminate:nil]; });
            }];
            [NSApp activateIgnoringOtherApps:YES];
            [NSApp run];
            return 0;
        }
        if (![mode isEqual:@"info"]) {
            fprintf(stderr, "usage: easymaccopy [serve|info|install|uninstall|selftest]\n"
                            "  serve      share files both ways; a window opens and the other computer also appears in Finder as \"EasySuite\" (default)\n"
                            "  info       show cable status and exit\n"
                            "  install    start automatically at login (so plugging the cable in is enough)\n"
                            "  uninstall  remove that\n"
                            "  selftest   check the protocol code without hardware\n");
            return 2;
        }
        io_service_t svc = findCable();
        if (!svc) { say(@"No EasySuite / OTi link cable found. Is it plugged in?"); return 1; }
        IOObjectRelease(svc);
        if (!openCable()) return 1;
        uint8_t ver[12] = {0}, bus[2] = {0}, pkt[2] = {0}, rs[8] = {0};
        otiCmd(0xF0, 0, 0, 0, 0, ver, sizeof ver, IN);
        otiCmd(0xD8, 0, 2, 0, 0, bus, sizeof bus, IN);
        otiCmd(0xD8, 0, 5, 0, 0, pkt, sizeof pkt, IN);
        otiCmd(0xD8, 0, 3, 0, 0, rs, sizeof rs, IN);
        say(@"Cable: chip %02X%02X%@, firmware %.6s, link USB %@, packet reg 0x%02X%02X",
            ver[2], ver[3], ver[2] == 0x21 && ver[3] == 0x08 ? @"" : @" (unrecognised)", (const char *)ver + 6,
            bus[0] == 0x20 ? @"2.0" : bus[0] == 0x11 ? @"1.1" : @"?", pkt[0], pkt[1]);
        say(@"PC side: %@", rs[0] >= 5 && rs[0] <= 7 ? @"EasySuite running" : @"not connected / EasySuite not running");
        closeCable();
        return 0;
    }
}
