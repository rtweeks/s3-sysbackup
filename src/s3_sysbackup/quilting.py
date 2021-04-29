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
from datetime import datetime, timedelta
import functools
import gzip
import hashlib
import io
import json
import os.path
import shutil
import sqlite3
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

class _NoExistingVersion(Exception):
    """Raised if a file's content does not exist on S3"""

class _AdequateRetentionExists(Exception):
    """Raised when additional retention is not necessary for the given object version"""

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
        
        with _FileContentHandler(self) as content_handler:
            with self._open_target_file(fpath) as origf:
                content_handler.prep_content(origf, lock_timeout=self.lock_timeout)
            
            self.manifest[fpath] = content_handler.save_to_bucket()
    
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
                zf = resources.enter_context(gzip.GzipFile(
                    mode='wb',
                    fileobj=self._Adapter(consume_gzipped),
                    
                    # Use fixed timestamp so MD-5 post-hash is equal for equal content
                    mtime=946684800, # 2000-01-01 00:00:00 UTC
                ))
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

class _FileContentHandler:
    extra_retention = timedelta(days=7)
    
    def __init__(self, quilter: Quilter):
        super().__init__()
        self._resources = ExitStack()
        self.extra_args = {'Metadata': {}}
        self.quilter = quilter
    
    def __enter__(self, ):
        self._resources.__enter__()
        self.backup_content = self.bound(TemporaryFile())
        return self
    
    def __exit__(self, *args):
        self._resources.__exit__(*args)
    
    @property
    def bucket(self):
        return self.quilter.bucket
    
    @property
    def s3(self):
        return self.quilter.s3
    
    @property
    def object_loc(self):
        return dict(Bucket=self.bucket, Key=self.content_key)
    
    def bound(self, resource):
        return self._resources.enter_context(resource)
    
    def prep_content(self, origf, *, fpath=None, lock_timeout=None):
        self.fpath = origf.name if fpath is None else fpath
        
        # Make a local, temporary copy of the file (holding a flock on the source for the duration)
        with backup_flock(origf, lock_timeout) as read_lock:
            self.locked_for_read = read_lock.obtained
            self.content_info = ci = _FilePrepStream(origf).stream_to(self.backup_content.write)
        self.backup_content.seek(0)
        
        if ci.content_compressed:
            _log.info("gzip-compressed content from %r", self.fpath)
        self.extra_args['Metadata']['storage-encoding'] = 'gzip'
        if _log.isEnabledFor(logging.INFO):
            _log.info(
                "Compressed %d bytes to %d bytes (%.1f%%)",
                ci.input_byte_count,
                ci.output_byte_count,
                ci.compression_ratio * 100,
            )
        
        self.content_key = "content/" + ci.content_hexdigest
        _log.info("Content key for %r: %s", self.fpath, self.content_key)
    
    def save_to_bucket(self, ):
        try:
            self.version_id = self._get_existing_version_id()
            if self.version_id is None:
                raise _NoExistingVersion
            
            if self._local_record_shows_adequate_retention():
                raise _AdequateRetentionExists
            
            if self._s3_shows_adequate_retention():
                raise _AdequateRetentionExists
            
            self._extend_retention_of_existing_version()
            
        except _AdequateRetentionExists:
            pass
        except Exception as e:
            if not isinstance(e, (AwsError, _NoExistingVersion)):
                _log.exception("Storing file content due to error: %s", e)
            
            self._put_content_object()
        
        _log.info("incorporating file %r in manifest", self.fpath)
        file_rec = File(
            get_ownership(self.fpath),
            get_permissions(self.fpath),
            self.content_key,
            self.version_id,
            storage_id(self.fpath),
        )
        if not self.locked_for_read:
            file_rec.unlocked_copy = True
        return file_rec
    
    def _put_content_object(self, ):
        _log.info(
            "Storing file content for %r at s3://%s/%s",
            self.fpath,
            self.bucket,
            self.content_key,
        )
        self.extra_args.update(self.quilter._retention_args(
            prefix='ObjectLock',
            extra_time=self.extra_retention,
        ))
        put_object_response = self.s3.put_object(
            **self.object_loc,
            Body=self.backup_content,
            ContentMD5=self.content_info.aws_integrity(),
            **self.extra_args,
        )
        _log.info("Content of %r stored in S3", self.fpath)
        self.version_id = put_object_response['VersionId']
        self._record_retention_locally(
            self.extra_args['ObjectLockRetainUntilDate']
        )
    
    def _get_existing_version_id(self, ):
        version_records = self.quilter._get_content_version_records(
            self.content_key
        )
        valid_versions = list(
            v_rec['VersionId'] for v_rec in version_records
            if self.content_info.matches_etag(v_rec['ETag'])
        )
        
        # If there is at least one INvalid version, log an error requesting manual review
        if len(version_records) > len(valid_versions):
            _log.error(
                "Key %r has more than one stored version;"
                " manual review of versions suggested",
                self.content_key,
            )
        
        # If there are no valid versions, we need to upload
        if not valid_versions:
            return None
        
        return valid_versions[0]
    
    def _extend_retention_of_existing_version(self, ):
        update_retention_kwargs = dict(
            **self.object_loc,
            VersionId=self.version_id,
            Retention=self.quilter._retention_args(
                extra_time=self.extra_retention,
            ),
        )
        _log.debug(
            "Object retention update kwargs: %r",
            update_retention_kwargs,
        )
        self.s3.put_object_retention(**update_retention_kwargs)
        _log.info(
            "Object retention for s3://%s/%s set; no upload needed",
            self.bucket,
            self.content_key,
        )
        
        try:
            self._record_retention_locally(
                update_retention_kwargs['Retention']['RetainUntilDate']
            )
        except Exception as e:
            _log.exception("While recording local retention: %s", e)
    
    def _local_record_shows_adequate_retention(self, ):
        try:
            return self.quilter.retain_until.timestamp() <= self._locally_stored_retention()
        except Exception:
            return False
    
    def _s3_shows_adequate_retention(self, ):
        try:
            retention_info = self.s3.get_object_retention(
                **self.object_loc,
                VersionId=self.version_id,
            )['Retention']
            retained_until = retention_info['RetainUntilDate']
            
            try:
                self._record_retention_locally(retained_until)
            except Exception as e:
                _log.exception("While recording local retention: %s", e)
            
            return retained_until > self.quilter.retain_until
        except Exception:
            return False
    
    def _locally_stored_retention(self, ):
        try:
            self._ensure_retention_table()
            conn = _get_db_conn()
            
            result = 0
            rows = conn.execute("""
                SELECT expires FROM retention
                WHERE bucket = ?
                AND key = ?
                AND version_id = ?
            """, (self.bucket, self.content_key, self.version_id))
            return max((r[0] for r in rows), default=0)
        except Exception as e:
            _log.exception("While querying local retention info: %s", e)
            return 0
    
    def _record_retention_locally(self, expiration: datetime):
        self._ensure_retention_table()
        conn = _get_db_conn()
        
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO retention (bucket, key, version_id, expires)
                VALUES (?, ?, ?, ?)
            """, (
                self.bucket,
                self.content_key,
                self.version_id,
                expiration.timestamp(),
            )).close()
    
    def _ensure_retention_table(self, ):
        conn = _get_db_conn()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS retention (
                    bucket TEXT,
                    key TEXT,
                    version_id TEXT,
                    expires INT,
                    CONSTRAINT pkey PRIMARY KEY (bucket, key, version_id)
                )
            """).close()

_db_conn = None
def _get_db_conn():
    global _db_conn
    if _db_conn is not None:
        try:
            _db_conn.execute("select sqlite_version()").close()
        except sqlite3.ProgrammingError:
            _db_conn = None
    
    if _db_conn is None:
        _db_conn = sqlite3.connect("/var/cache/backup/retention.db")
    
    return _db_conn
