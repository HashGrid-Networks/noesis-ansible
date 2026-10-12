#!/usr/bin/env python3
"""Darwin setuid worker-write probe. No secrets. Fail closed.

argv: <uid> <gid> <directory>
Writes only <directory>/.prodqual-worker-probe-<pid>-<rand> and unlinks it.

rc 0: write succeeded and the temporary file was unlinked (allow axis only)
rc 13: EACCES or EPERM on the open
rc 2: other OSError, missing path, not a directory, probe already exists,
      or unexpected isolation failure (allow path denied a probe that wrote)
rc 3: argv invalid, interpreter mismatch, setuid/setgid failure, identity
      mismatch
rc 4: any other caught exception
"""
from __future__ import annotations

import errno
import os
import sys


def _diag(rc, path, err=None):
    base = os.path.basename(path) if path else ""
    extra = ""
    if err is not None and getattr(err, "errno", None) is not None:
        extra = " errno=%s" % err.errno
    sys.stderr.write("rc=%s%s path=%s\n" % (rc, extra, base))


def _fail(rc, path, err=None):
    _diag(rc, path, err)
    return rc


def _new_probe_name():
    if hasattr(os, "getrandom"):
        entropy = int.from_bytes(os.getrandom(8, flags=os.GRND_NONBLOCK), "big")
    else:
        entropy = id(object())
    return ".prodqual-worker-probe-%d-%d" % (os.getpid(), entropy)


def main(argv):
    path = ""
    try:
        if len(argv) != 4:
            return _fail(3, "")
        exe = os.path.basename(sys.executable)
        if not exe.startswith("python3"):
            return _fail(3, argv[3] if len(argv) > 3 else "")
        uid = int(argv[1])
        gid = int(argv[2])
        path = argv[3]
    except (TypeError, ValueError):
        return _fail(4, path)
    except Exception as exc:
        return _fail(4, path, exc)

    try:
        os.setgid(gid)
        os.setuid(uid)
    except PermissionError as exc:
        return _fail(3, path, exc)
    except OSError as exc:
        return _fail(3, path, exc)
    except Exception as exc:
        return _fail(4, path, exc)

    if not (os.getuid() == uid and os.getgid() == gid):
        return _fail(3, path)

    probe_name = _new_probe_name()
    probe_path = path + "/" + probe_name
    if os.path.basename(probe_path) != probe_name:
        return _fail(2, path)

    try:
        fd = os.open(
            probe_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except PermissionError as exc:
        return _fail(13, probe_path, exc)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return _fail(13, probe_path, exc)
        return _fail(2, probe_path, exc)
    except Exception as exc:
        return _fail(4, probe_path, exc)

    try:
        os.close(fd)
    except OSError as exc:
        return _fail(2, probe_path, exc)
    except Exception as exc:
        return _fail(4, probe_path, exc)

    try:
        os.unlink(probe_path)
    except OSError as exc:
        return _fail(2, probe_path, exc)
    except Exception as exc:
        return _fail(4, probe_path, exc)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
