# EasySuite for Linux

Same cable protocol as the Mac and Windows apps. This program logs in as a Mac-class peer (OS code `0x14`), so it writes big-endian payloads and POSIX paths. Windows peers still see an ordinary Mac. The login token stays `MACOSX` so the original Windows EasySuite accepts it; the OS byte is what tells a current Mac or Windows app that this side is Linux.

```bash
sudo apt install build-essential libgtk-3-dev libfuse3-dev fuse3 pkg-config
make
./easysuite
```

You need permission to open `/dev/sg*` (usually group `disk` or root) and to mount a FUSE filesystem (`fusermount3`, no extra daemon). The other computer shows up in the GTK window and, when FUSE mounts, as a folder at `~/EasySuite` which the file manager can browse.

`make selftest` checks the protocol without the cable, GTK, or FUSE. On a Mac that is all `make` does, because the GTK and FUSE headers are not part of the Mac build. The window needs GTK 3.16 or newer and libfuse 3.2 or newer (`fuse_new` / `fuse_mount` and `gtk_label_set_xalign`).
