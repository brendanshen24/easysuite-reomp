# EasySuite for Windows

File window for the OTi / Targus EasySuite USB link cable. It is both the client and the server, so it talks to a Mac, another Windows PC, or Linux.

```bash
make            # easysuite.exe, with mingw-w64
make selftest   # protocol checks, no cable
```

Copy `easysuite.exe` to the PC and run it. Plug in the cable, then start EasySuite on the other computer (`easymaccopy serve` on a Mac, `./easysuite` on Linux, or this same exe). Drives on the other computer show up in the window. There is no localhost drive letter: Windows usually refuses to mount a WebDAV disk on 127.0.0.1.

Log: `%TEMP%\easysuite.log`.
