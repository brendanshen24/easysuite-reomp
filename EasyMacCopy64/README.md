# easymaccopy — EasySuite cable support for 64-bit / Apple Silicon Macs

The Targus USB-to-USB transfer cable (OTi chip, USB `0EA0:2108`, product name "EasySuite") came with
`EasyMacCopy.app`, a 2007 **PowerPC-only** program. Rosetta 2 can't run PowerPC code, so it can't run on any
current Mac. `easymaccopy` is a from-scratch native rewrite (universal: arm64 + x86_64, macOS 10.13+) built from
the protocol recovered out of that binary. It needs no kernel extension; it uses Apple's built-in SCSI user client.

## Use

```bash
make                      # builds ./easymaccopy (universal)
./easymaccopy selftest    # protocol checks, no hardware needed
./easymaccopy info        # cable status
./easymaccopy serve       # window plus a Finder disk named EasySuite
```

The other two programs live next to this folder:

```bash
# Windows, from a Mac with mingw-w64, or on Windows with mingw
make -C ../EasySuiteWin              # easysuite.exe
make -C ../EasySuiteWin selftest

# Linux (libgtk-3-dev, libfuse3-dev, fuse3)
make -C ../EasySuiteLinux            # ./easysuite
make -C ../EasySuiteLinux selftest   # protocol only; also works on a Mac
```

1. Plug the cable into both computers.
2. Start the app on each one and leave it running: `./easymaccopy serve` on a Mac, `easysuite.exe` on Windows, `./easysuite` on Linux. The old EasySuite.exe from the cable's CD still works on Windows.
3. Copy from either side:
   - **The EasySuite window** on every platform (name, size, date, folders, up / refresh / new folder / delete / rename / download / upload).
   - **Finder,** on a Mac. The other computer is also a disk named **EasySuite**.
   - **The file manager,** on Linux, at `~/EasySuite` (a FUSE folder; no extra daemon). Windows does not get a drive letter: its WebClient service usually refuses a disk on localhost, so the window is the file manager there.

Every pairing works: Mac–PC, PC–Mac, PC–PC, Mac–Mac, and the same with Linux (Linux–Mac, Mac–Linux, Linux–PC, PC–Linux, Linux–Linux). Each side is both a server and a client. Windows writes little-endian and `C:\` paths. Mac and Linux write big-endian. Linux logs in as a Mac-class peer (OS code `0x14`, POSIX paths, login token `MACOSX`) so the original Windows program still accepts it. The OS byte is how a current app tells Linux from Mac.

`install` and `uninstall` are still there (`./easymaccopy install`). `install` copies the program to `~/Library/Application Support/EasyMacCopy` (launchd will not run a program that lives in Desktop or Documents) and loads a login item. Its log is `~/Library/Logs/easymaccopy.log`. Run `serve` from Terminal the first time. macOS can refuse a copy that lives in the Desktop folder when something other than Terminal launches it; `install` puts it somewhere that is allowed to open the cable.

Each side can reach the files the account on the other computer can reach. macOS may ask for permission the first time Desktop, Documents and similar folders are opened. On Linux, opening `/dev/sg*` usually means being in the `disk` group or running as root, and FUSE needs `fusermount3`.

## What was reverse engineered

Sources: `EasyMacCopy.app/Contents/Resources/EasyMacCopy.tgz`, which contains the real PPC app (the outer
binary is a stub), decompiled with Ghidra. The method table was recovered from the ObjC1 metadata.

**Transport.** The cable enumerates as a SCSI CD-ROM (MMC "authoring" device). Its built-in CD holds the
Windows installer. The app unmounts that CD, takes exclusive access through `SCSITaskLib`, and sends 16-byte
vendor CDBs with `'O','T'` in bytes 14–15:

| CDB | Meaning |
|---|---|
| `F0` | chip/firmware: 12 bytes, `[2..3] = 21 08`, `[6..11]` = date |
| `D8 00 02` | link speed: `[0]` ours, `[1]` remote (`0x20` USB 2.0, `0x11` USB 1.1) |
| `D8 01 05 00 7F` | set packet-size register (done at start) |
| `D8 00 03 hi lo` | poll and book `hi:lo` outgoing packets → `[0]` 0/1 remote app absent, 5 = `[1..2]` packets waiting for us, 6/7 = send |
| `D9 28 64` | receive one 64 KB packet |
| `D9 2A FF` | send one 64 KB packet |

Errors come back as sense data: sense key 9, ASC `0x80`–`0x89` = OTi status codes.

**Packets.** 64 KB each, with a 20-byte little-endian header `{counter, session, index, total, dataLen}`.
Messages longer than `0xFFEC` bytes are split across packets and reassembled per session.

**Messages.** Byte 0 is the command: below `0xA0` is a request, `0xA0` and up a reply. Each side writes
multi-byte fields and UTF-16 text in its own native order. A PC is little-endian. A Mac (OS code ≥ 8 in its login)
is big-endian, as on PowerPC. This port keeps the big-endian wire format so the Windows program sees an
ordinary Mac.

| Req | | Reply | |
|---|---|---|---|
| `01` | login `[os]…"MACOSX"` | `A1` | result `[cmd][result][u32][errno][u64][u8][len]` |
| `04` | list dir `[len][path]` | `A2` | `[count]` + 552-byte entries `{attr, ctime, atime, mtime, size, nameLen, name[256]}` |
| `06`/`08` | delete dir/file | `A3` | file block `[id][blocks][index][len][data]`, 0x9F81F bytes each |
| `07` | mkdir | `A4` | volume list (count is little-endian even from a Mac) |
| `09` | rename | `A5`/`A9` | write/read failure + UTF-16 text |
| `0C` | upload block (same layout as `A3`) | `A6` | zero-length file IDs |
| `10`/`11` | download list / cancel | `A7` | download finished |
| `12`/`13`/`14`/`15` | upload list / pre-check / cancel / empty files | `A8` | pre-check: free space, existing file IDs |
| `37` | set mode and dates | | |

**Mac as the client.** The same requests, built the way the PowerPC app built them (big-endian fields, UTF-16 big-endian with the BOM stripped). A Windows path looks like `C:\dir\file`. A Mac or Linux path looks like `/home/me` or `/Volumes/Macintosh HD/Users`. The volume list (`A4`) always stores its count little-endian. For a Windows peer the drive letter is what matters (`C` → `C:\`); for a Mac or Linux peer the path that follows the letter is the real root.

| Req | Layout |
|---|---|
| `04` list | `[u16 len][path]` |
| `06` / `08` delete dir / file | `[u32 session][u16 len][path]`. Folders must be empty, so a recursive delete lists first, removes children, then the folder. |
| `07` mkdir, `09` rename | same header; rename is `[len1][len2][old path][new path]` |
| `10` download | `[u32 session][u16 count]` then `{u32 fileID, u16 len, path}` |
| `11` cancel download | `[u32 session][u32 fileID]` |
| `13` upload pre-check | `[u32 session][u64 total size][u16 largeFileCount=0][u16 count]` then the same file entries. The `A8` reply is `[shareReadOnly][enoughSpace][fsFlag][destReadOnly][u32 session][u32 existCount][fileIDs…]` |
| `12` / `15` file list / empty files | `[u32 session][u16 count]` then file entries. Empty files use `15` and create the file with no data blocks. |
| `0C` upload block | same 17-byte header as `A3`: `[fileID][blockCount][index][len][data]`, 0x9F81F bytes of file data |

A directory entry is the same 552 bytes from either side. Times are Unix seconds. `FILE_ATTRIBUTE_DIRECTORY` (`0x10`) marks a folder. Drive lists (`A4`) use a little-endian count, then `{letter, type}` pairs. `A:` and `B:` are skipped on Windows. A Mac or Linux peer sends letter `A` for every volume and then the real name and POSIX path, in big-endian.

Finder does not speak this protocol. On a Mac, `serve` runs a WebDAV server on `127.0.0.1` and mounts it with NetFS, so Finder's list / get / put / mkdir / delete / rename turn into the requests above. The EasySuite window does the same requests directly. On Linux the FUSE folder does too.

## Differences from the original

- The other computer's disks show up in Finder, named **EasySuite**, and in an EasySuite window on the Mac. `EasySuiteWin/easysuite.exe` is the Windows program (a file window, because Windows often refuses a WebDAV disk on localhost). `EasySuiteLinux/easysuite` is the Linux program (GTK window plus a FUSE folder). The old EasySuite.exe still works against the Mac and Linux apps.
- Linux uses OS code `0x14` and the same big-endian layout as a Mac, so Mac–Linux, Linux–PC, and Linux–Linux need no third byte order. Mac to Mac and PC to PC work the same way. A current app tells the systems apart by the OS byte (`0x13` Mac, `0x14` Linux, anything under 8 Windows).
- Overwriting a file truncates it first. The original left old bytes behind when the new file was shorter.
- The original's cable "licence" check (an expiry date in the cable's flash) is skipped.
- Single-threaded loop instead of three threads. Timing and queue sizes match the original:
  a booking window of 15 packets, or 50/100 when both ends are USB 2.0.
