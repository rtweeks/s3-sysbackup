# s3-sysbackup - Efficient, Unix-philosophy backup to S3 for Linux
# Copyright (c) 2021 Richard T. Weeks
# 
# GNU GENERAL PUBLIC LICENSE
#    Version 3, 29 June 2007
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import boto3 # package boto3
from botocore.exceptions import ClientError as AwsError # package boto3
from contextlib import ExitStack
import gzip
import hashlib
import json
import os.path
import shutil
from tempfile import TemporaryFile

from .fs import (
    compresses_well,
    directories_containing,
    get_ownership,
    get_permissions,
    linkchain,
    storage_id,
    time_limited_flock,
)
from .utils import (
    BackupFacilitator,
    FileHasher,
    S3IntegrityHasher,
    _sublogger,
)

import logging
_log = logging.getLogger(__name__)

class TargetFileError(Exception):
    """Raised if an identified backup target cannot be opened for an identified reason"""
    def __init__(self, file: str):
        super().__init__(file)
    
    @property
    def file(self) -> str:
        return self.args[0]
    
    def __str__(self, ):
        cause = self.__cause__
        if isinstance(cause, PermissionError):
            return "user {!r} lacks permission to read target {!r}".format(
                getuser(),
                self.file
            )
        if isinstance(cause, FileNotFoundError):
            return "target {!r} not found on system".format(self.file)
        return "unable to open target {!r}".format(self.file)

class Quilter(BackupFacilitator):
    def __init__(self, bucket: str, *,
        manifest_prefix: str = '',
        s3_client=None,
        lock_timeout=2,
        **kwargs
    ):
        super().__init__(bucket, **kwargs)
        self.manifest_prefix = manifest_prefix
        self.manifest = {}
        self.s3 = s3_client or boto3.client('s3')
        self.lock_timeout = lock_timeout
    
    def add(self, fpath):
        _log.info("picking file at %r", fpath)
        links, fpath = linkchain(fpath)
        if not os.path.isfile(fpath):
            return
        if fpath in self.manifest:
            return
        for link, target in links:
            if link in self.manifest:
                continue
            _log.info("incorporating symlink %r in manifest", link)
            self.manifest[link] = Symlink(get_ownership(link), target)
            self._include_directories(link)
        
        self._include_directories(fpath)
        
        # Make a local, temporary copy of the file (holding a flock on the source for the duration)
        with ExitStack() as resources:
            f = resources.enter_context(TemporaryFile())
            
            # TODO: Try to use reflink to make a copy-on-write (i.e. lightweight)
            # copy of the file to work with instead of an actual file-copy operation
            with self._open_target_file(fpath) as origf:
                with time_limited_flock(origf, self.lock_timeout) as read_lock:
                    locked_for_read = read_lock.locked
                    shutil.copyfileobj(origf, f)
            f.seek(0)
            
            compress_content = compresses_well(f)
            f.seek(0)
            
            sha256hash = hashlib.sha256()
            md5_hash = S3IntegrityHasher()
            FileHasher(sha256hash, md5_hash).consume(f, 1 << 20)
            f.seek(0)
            content_key = "content/" + sha256hash.hexdigest()
            _log.info("content key for %r: %s", fpath, content_key)
            
            object_loc = dict(Bucket=self.bucket, Key=content_key)
            
            try:
                update_retention_kwargs = dict(
                    **object_loc,
                    Retention=self._retention_args(),
                )
                _log.debug(
                    "object retention update kwargs: %r",
                    update_retention_kwargs,
                )
                self.s3.put_object_retention(**update_retention_kwargs)
                _log.info(
                    "object retention set for s3://%s/%s; no upload needed",
                    self.bucket,
                    content_key
                )
            except AwsError as e:
                # Sadly, we can't test for a "NoSuchKey" error as S3 sometimes returns an "AccessDenied" instead
                
                if compress_content:
                    _log.info("gzip-compressing content from %r", fpath)
                    zf = resource.enter_context(TemporaryFile())
                    shutil.copyfileobj(f, gzip.GzipFile(None, 'wb', fileobj=zf))
                    if _log.isEnabledFor(logging.INFO):
                        sizes = (zf.tell(), f.tell())
                        ratio = 1 - (sizes[0] / sizes[1])
                        _log.info(
                            "compressed %d byes to %d bytes (%.1f%%)",
                            *sizes,
                            ratio * 100,
                        )
                    f.close()
                    zf.seek(0)
                    f = zf
                
                _log.info(
                    "storing file content for %r at s3://%s/%s",
                    fpath,
                    object_loc['Bucket'],
                    object_loc['Key'],
                )
                self.s3.put_object(
                    **object_loc,
                    Body=f,
                    ContentMD5=md5_hash.aws_integrity(),
                    **extra_args,
                )
                _log.info("content of %r stored in S3", fpath)
        
        # Accumulate this file into the manifest
        _log.info("incorporating file %r in manifest", fpath)
        file_rec = File(
            get_ownership(fpath),
            get_permissions(fpath),
            content_key,
            storage_id(fpath),
        )
        if not locked_for_read:
            file_rec.unlocked_copy = True
        self.manifest[fpath] = file_rec
    
    def get_manifest_jsonl_lines(self, *, as_str: bool = True):
        for path in sorted(self.manifest):
            line_data = dict(
                self.manifest[path].json_data,
                path=path,
            )
            if as_str:
                yield json.dumps(line_data).replace("\n", " ")
            else:
                yield line_data
    
    def upload_manifest(self, ):
        extra_args = dict(
            ContentType='application/x-jsonlines',
        )
        extra_args.update(self._retention_args(prefix='ObjectLock'))
        with TemporaryFile() as f:
            with _sublogger('content_manifest', section='manifest') as manifest_log:
                for line in self.get_manifest_jsonl_lines():
                    manifest_log.note("%s", line)
                    f.write(line.encode('ascii') + b'\n')
                f.flush()
            f.seek(0)
            # WON'T BE ABLE TO USE upload_file OR upload_fileobj BECAUSE THEY DON'T SUPPORT Object Lock
            md5_hash = S3IntegrityHasher()
            FileHasher(md5_hash).consume(f, 1 << 20)
            f.seek(0)
            manifest_key = self.manifest_prefix + self._hostify('content_manifest.jsonl')
            _log.info("uploading content manifest to s3://%s/%s", self.bucket, manifest_key)
            self.s3.put_object(
                Bucket=self.bucket,
                Key=manifest_key,
                Body=f,
                ContentMD5=md5_hash.aws_integrity(),
                **extra_args,
            )
            _log.info("content manifest stored in S3")
    
    def _include_directories(self, fpath):
        for d in directories_containing(fpath):
            if d in self.manifest:
                break
            _log.info("incorporating directory %r in manifest", d)
            self.manifest[d] = Directory(get_ownership(d), get_permissions(d))
    
    def _open_target_file(self, file, **kwargs):
        kwargs['mode'] = 'rb'
        try:
            return open(file, **kwargs)
        except (FileNotFoundError, PermissionError) as e:
            raise TargetFileError(file) from e

class Symlink:
    def __init__(self, ownership, target):
        super().__init__()
        self.ownership = ownership
        self.target = target
    
    @property
    def json_data(self):
        return {'typ': 'l', **self.ownership, 'tgt': self.target}

class Directory:
    def __init__(self, ownership, perms_dict):
        super().__init__()
        self.ownership = ownership
        self.perms_dict = {}
        for k in ('acl', 'mode'):
            if k in perms_dict:
                self.perms_dict[k] = perms_dict[k]
                break
    
    @property
    def json_data(self):
        return {'typ': 'd', **self.ownership, **self.perms_dict}

class File:
    unlocked_copy = False
    
    def __init__(self, ownership, perms_dict, content_key, storage_id):
        super().__init__()
        self.ownership = ownership
        self.perms_dict = {}
        for k in ('acl', 'mode'):
            if k in perms_dict:
                self.perms_dict[k] = perms_dict[k]
                break
        self.content_key = content_key
        self.storage_id = storage_id
    
    @property
    def json_data(self):
        result = {
            'typ': 'f',
            **self.ownership,
            **self.perms_dict,
            'dat': self.content_key,
            'id': self.storage_id,
        }
        if self.unlocked_copy:
            result.setdefault('w', []).append('unlocked-copy')
        return result
