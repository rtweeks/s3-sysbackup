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

from base64 import b64encode
from binascii import hexlify, unhexlify
import boto3 # package boto3
from botocore.exceptions import ClientError as AwsError # package boto3
from contextlib import ExitStack
from collections import defaultdict
import functools
import gzip
import hashlib
import io
import json
import os.path
import shutil
from tempfile import TemporaryFile
from typing import Any, Callable, List

from .fs import (
    compresses_well,
    directories_containing,
    get_ownership,
    get_permissions,
    linkchain,
    storage_id,
    backup_flock,
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

class _NonconformingLatestVersionError(Exception):
    """Raised if a mismatch between object key and content is detected"""

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
        self._retained_versions_info = None
    
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
            extra_args = {'Metadata': {}}
            extra_args.update(self._retention_args(prefix='ObjectLock'))
            
            # TODO: Try to use reflink to make a copy-on-write (i.e. lightweight)
            # copy of the file as a starting point to avoid a "partial write";
            # still do this in the context of a LOCK_SH flock on the file (if
            # quickly available).
            with self._open_target_file(fpath) as origf, backup_flock(origf, self.lock_timeout) as read_lock:
                locked_for_read = read_lock.obtained
                backup_content_info = _FilePrepStream(origf).stream_to(f.write)
            f.seek(0)
            
            if backup_content_info.content_compressed:
                _log.info("gzip-compressing content from %r", fpath)
                extra_args['Metadata']['storage-encoding'] = 'gzip'
                if _log.isEnabledFor(logging.INFO):
                    sizes = (zf.tell(), f.tell())
                    ratio = 1 - (sizes[0] / sizes[1])
                    _log.info(
                        "compressed %d byes to %d bytes (%.1f%%)",
                        backup_content_info.input_byte_count,
                        backup_content_info.output_byte_count,
                        backup_content_info.compression_ratio * 100,
                    )
            
            content_key = "content/" + backup_content_info.content_hexdigest
            _log.info("content key for %r: %s", fpath, content_key)
            
            object_loc = dict(Bucket=self.bucket, Key=content_key)
            
            try:
                version_records = self._get_content_version_records(
                    content_key
                )
                existing_version_id = None
                valid_versions = list(
                    v_rec['VersionId'] for v_rec in version_records
                    if backup_content_info.matches_etag(v_rec['ETag'])
                )
                
                # If there is at least one INvalid version, log an error requesting manual review
                if len(version_records) > len(valid_versions):
                    _log.error("Key %r has more than one stored version; manual review of versions suggested", content_key)
                
                # If there is at least one valid version, try extending that version's retention period
                if len(valid_versions) > 0:
                    existing_version_id = valid_versions[0]
                else:
                    # Otherwise, we'll have to upload
                    raise _NonconformingLatestVersionError(self.bucket, content_key)
                
                # TODO: Use a local database to check if we know we set a long-enough retention period
                
                update_retention_kwargs = dict(
                    **object_loc,
                    VersionId=existing_version_id,
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
                version_id = existing_version_id
                
                # TODO: Update the local database to let it know we set the retention period
            except (AwsError, _NonconformingLatestVersionError) as e:
                # Sadly, we can't test for a "NoSuchKey" error as S3 sometimes returns an "AccessDenied" instead
                
                _log.info(
                    "storing file content for %r at s3://%s/%s",
                    fpath,
                    object_loc['Bucket'],
                    object_loc['Key'],
                )
                put_object_response = self.s3.put_object(
                    **object_loc,
                    Body=f,
                    ContentMD5=backup_content_info.aws_integrity(),
                    **extra_args,
                )
                _log.info("content of %r stored in S3", fpath)
                version_id = put_object_response['VersionId']
                
                # TODO: Update the local database with the new retention period information for this object
        
        # Accumulate this file into the manifest
        _log.info("incorporating file %r in manifest", fpath)
        file_rec = File(
            get_ownership(fpath),
            get_permissions(fpath),
            content_key,
            version_id,
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
    
    def _get_content_version_records(self, content_key: str) -> List[str]:
        self._load_content_listing()
        return self._retained_versions_info.get(content_key, [])
    
    # MINIMIZE LIST CALLS!!!
    def _load_content_listing(self):
        if self._retained_versions_info is not None:
            return
        
        self._retained_versions_info = ver_info_dict = {}
        lov_kwargs = dict(
            Bucket=self.bucket,
            Prefix='content/',
        )
        while lov_kwargs.get('KeyMarker', True):
            lov_response = self.s3.list_object_versions(**lov_kwargs)
            # Prepare for next iteration
            lov_kwargs['KeyMarker'] = lov_response.get('NextKeyMarker', '')
            lov_kwargs['VersionIdMarker'] = lov_response.get('NextVersionIdMarker', '')
            
            for ver_rec in lov_response.get('Versions', ()):
                ver_info_dict.setdefault(ver_rec['Key'], []).append(ver_rec)

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
    
    def __init__(self, ownership, perms_dict, content_key, version_id, storage_id):
        super().__init__()
        self.ownership = ownership
        self.perms_dict = {}
        for k in ('acl', 'mode'):
            if k in perms_dict:
                self.perms_dict[k] = perms_dict[k]
                break
        self.content_key = content_key
        self.version_id = version_id
        self.storage_id = storage_id
    
    @property
    def json_data(self):
        result = {
            'typ': 'f',
            **self.ownership,
            **self.perms_dict,
            'dat': self.content_key,
            'ver': self.version_id,
            'id': self.storage_id,
        }
        if self.unlocked_copy:
            result.setdefault('w', []).append('unlocked-copy')
        return result

class _FilePrepStream:
    def __init__(self, source):
        super().__init__()
        self.sha256_prehash = hashlib.sha256()
        self.md5_prehash = hashlib.sha256()
        self.input_byte_count = 0
        self.md5_posthash = hashlib.md5()
        self.output_byte_count = 0
        self._source = source
    
    class Result:
        content_compressed = False
        sha256_prehash = None
        md5_prehash = None
        input_byte_count = None
        md5_posthash = None
        output_byte_count = None
        
        @property
        def content_hexdigest(self) -> str:
            return hexlify(self.sha256_prehash).decode('ascii')
        
        def aws_integrity(self, ) -> str:
            return b64encode(self.md5_posthash).decode('ascii')
        
        def matches_etag(self, etag) -> bool:
            if etag[0] != etag[-1] and etag[0] not in '"\'':
                return False
            etag_val = unhexlify(etag[1:-1])
            return etag_val in (self.md5_prehash, self.md5_posthash)
        
        @property
        def compression_ratio(self):
            return 1 - (self.output_byte_count / self.input_byte_count)
    
    @property
    def source(self):
        return self._source
    
    def stream_to(self, consume: Callable[[bytes], Any], *, chunksize=1<<18):
        result = self.Result()
        buf = self.source.read(chunksize)
        
        compress_stream = compresses_well(io.BytesIO(buf))
        with ExitStack() as resources:
            if compress_stream:
                result.content_compressed = True
                consume_gzipped = functools.partial(self._posthash_and_consume, consume)
                zf = resources.enter_context(
                    gzip.GzipFile(None, 'wb', fileobj=self._Adapter(consume_gzipped))
                )
                consume = lambda buf: zf.write(buf) if buf else zf.flush()
            else:
                consume = functools.partial(self._posthash_and_consume, consume)
            
            self.sha256_prehash.update(buf)
            self.md5_prehash.update(buf)
            self.input_byte_count += len(buf)
            consume(buf)
            
            for buf in self._remaining_chunks(self.source, chunksize):
                self.sha256_prehash.update(buf)
                self.md5_prehash.update(buf)
                self.input_byte_count += len(buf)
                consume(buf)
            
            consume(b'')
        
        result.sha256_prehash, self.sha256_prehash = self.sha256_prehash.digest(), hashlib.sha256()
        result.md5_prehash, self.md5_prehash = self.md5_prehash.digest(), hashlib.md5()
        result.md5_posthash, self.md5_posthash = self.md5_posthash.digest(), hashlib.md5()
        result.input_byte_count, self.input_byte_count = self.input_byte_count, 0
        result.output_byte_count, self.output_byte_count = self.output_byte_count, 0
        return result
    
    def _posthash_and_consume(self, consume, content):
        self.md5_posthash.update(content)
        self.output_byte_count += len(content)
        consume(content)
    
    class _Adapter:
        def __init__(self, consume):
            super().__init__()
            self.write = consume
        
        def flush(self):
            pass
    
    def _remaining_chunks(self, f, chunksize):
        while True:
            buf = f.read(chunksize)
            if not buf:
                break
            yield buf
