# Copyright 2021 Richard T. Weeks
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tools for inspecting the filesystem tree"""
from contextlib import contextmanager
import errno
import fcntl
import grp
import gzip
import hashlib
import io
import os, os.path
import pwd
import stat
import subprocess as subp
import time
from typing import Iterable, List, Tuple, Union as OneOf
import unicodedata
import warnings
try:
    from posix1e import ACL
except ImportError:
    warnings.warn(
        "Unable to import 'posix1e' (from 'pylibacl' package); falling back on getfacl"
    )
    ACL = None

from .utils import (
    _debug_log,
    namedtuple_def,
)

import logging
_log = logging.getLogger(__name__)

Path = OneOf[str, os.PathLike] # Referencing any filesystem entry
FilePath = OneOf[str, os.PathLike] # Referencing a file entry
BinaryReadableFile = OneOf[io.BufferedReader, io.BufferedRandom, io.BufferedRWPair]

@_debug_log(child='mount')
def mount(path: Path) -> str:
    """Get the mount point in the filesystem under which *path* is mounted
    
    If *path* is a mount point, it is returned.
    """
    path = os.path.realpath(path)
    while not os.path.ismount(path):
        path = os.path.dirname(path)
    return path

@_debug_log
def storage_id(fpath: FilePath) -> str:
    """Unique identifier of the file's storage location
    
    The result incorporates both the filetree path on which the *fpath* is
    mounted as well as the inode for *fpath* on that device.
    """
    mpath = unicodedata.normalize('NFKC', mount(fpath)).encode('utf8')
    inode = str(os.lstat(fpath)[stat.ST_INO]).encode('ascii')
    return hashlib.md5(b'\0'.join([mpath, inode])).hexdigest()

@_debug_log
def linkchain(path: Path) -> Tuple[List[Tuple[str, str]], str]:
    """Resolution of symbolic link chain
    
    The first element of the result is a :class:`list` of (link, target) pairs;
    this list will be empty if *path* is not a symlink.  The second element of
    the result is the final, non-symlink path in the chain of symlinks starting
    at *path*.
    """
    links = []
    while os.path.islink(path):
        target = os.readlink(path)
        links.append((str(path), target))
        path = target
    return (links, str(path))

@_debug_log
def directories_containing(path: Path) -> Iterable[str]:
    """Iterate directories containing *path*, ascending the filesystem tree"""
    d = os.path.dirname(path)
    while path != d:
        yield d
        path = d
        d = os.path.dirname(path)

@_debug_log
def get_ownership(path: Path) -> dict:
    """Get filesystem entry ownership information
    
    The returned :class:`dict` has two keys: ``'o'`` and ``'g'`` representing
    the owning user and group, respectively.  If these can be resolved to
    named entities (via :func:`pwd.getpwuid` and :func:`grp.getgrgid`), the
    symbolic name is used; otherwise, the value in the result is an
    :class:`int`.
    """
    pstat = os.stat(path)
    def numeric_fallback(fn, id):
        try:
            return fn(id)[0]
        except KeyError:
            return id
    
    return {
        'o': numeric_fallback(pwd.getpwuid, pstat.st_uid),
        'g': numeric_fallback(grp.getgrgid, pstat.st_gid),
    }

@_debug_log
def get_permissions(path: Path) -> dict:
    """Get filesystem entry permissions information (ACL or numeric mode)
    
    If possible, the file's ACL is retrieved and the :class:`dict` returned
    contains an ``'acl'`` entry; if :mod:`posix1e` is available, this is done
    in-process, falling back on invoking the `getfacl` program if not.
    
    """
    if ACL:
        acl = ACL(file=path).to_any_text()
        if isinstance(acl, bytes):
            acl = acl.decode('ascii')
        return {'acl': acl}
    
    # TODO: On Windows, use win32security to read the file's ACL
    
    if not getattr(get_permissions, '_no_getfacl', False):
        try:
            acl = subp.check_output(['getfacl', '-cE', path], encoding='utf8')
        except FileNotFoundError:
            get_permissions._no_getfacl = True
        except subp.CalledProcessError:
            pass
        else:
            return {'acl': acl}
    
    return {'mode': stat.S_IMODE(os.lstat(path)[stat.ST_MODE])}

@_debug_log
def compresses_well(file: BinaryReadableFile) -> bool:
    """Determine if the data in the given binary stream compresses well"""
    content = file.read(1 << 14)
    return (len(gzip.compress(content, 5)) < 0.7 * len(content))

@contextmanager
def backup_flock(fileobj, timeout_seconds, *, timestep=0.1):
    """Create a context manager with an attempted shared lock on a file
    
    Logs a warning if the advisory file lock cannot be obtained.
    
    The context value is a :class:`LockStatus` indicating whether the lock
    was successfully obtained.
    """
    deadline = time.time() + timeout_seconds
    locked = False
    while time.time() < deadline:
        try:
            fcntl.flock(fileobj, fcntl.LOCK_SH | fcntl.LOCK_NB)
            locked = True
            break
        except IOError as e:
            if e.errno != errno.EAGAIN:
                raise
            
            time.sleep(timestep)
    
    if not locked:
        if hasattr(fileobj, 'name'):
            _log.warning("Unable to lock %r for reading", fileobj.name)
        else:
            _log.warning("Unable to lock file for reading")
    
    try:
        yield LockStatus(locked)
    finally:
        if locked:
            fcntl.flock(fileobj, fcntl.LOCK_UN)

@namedtuple_def
def LockStatus():
    return 'obtained'
