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
from datetime import datetime
import os.path
import re
import subprocess as subp
from tempfile import TemporaryFile
from typing import Optional

from .utils import (
    BackupFacilitator,
    FileHasher,
    S3IntegrityHasher,
    _sublogger,
)

import logging
_log = logging.getLogger(__name__)

class Snapshotter(BackupFacilitator):
    def __init__(self, bucket: str, key_prefix: Optional[str] = None, *,
        manifest_prefix: str = '',
        s3_client=None,
        **kwargs
    ):
        super().__init__(bucket, **kwargs)
        if not self.use_host_prefix and key_prefix is None:
            raise ValueError("if 'use_host_prefix' is False, 'key_prefix' must be specified")
        self.key_prefix = key_prefix or ''
        self.manifest_prefix = manifest_prefix
        self.manifest = set() # Set of snapshot keys
        self.s3 = s3_client or boto3.client('s3')
    
    def record_from(self, fpath):
        key_part = "{ts}-{snap}".format(
            ts=datetime.utcnow().isoformat(timespec='minutes') + 'Z',
            snap=os.path.basename(fpath),
        )
        snapshot_key = self.key_prefix + self._hostify(key_part)
        with TemporaryFile() as f:
            _log.info("running snapshotter %r", fpath)
            metadata = subp.check_output(
                [fpath, str(f.fileno())],
                pass_fds=(f.fileno(),),
                encoding='utf8',
            )
            f.seek(0)
            
            # Scan the metadata for a "restore" command
            restore_cmd = self.extract_restore_cmd(metadata)
            
            # Upload this to S3
            extra_args = dict(Metadata={'backup-output': metadata.replace("\n", "; ")[-1000:]})
            md5_hash = S3IntegrityHasher()
            FileHasher(md5_hash).consume(f, 1 << 20)
            f.seek(0)
            if restore_cmd is not None:
                _log.info("identified restore command: %s", restore_cmd)
                extra_args['Metadata'].update({'restore-through': restore_cmd})
            extra_args.update(self._retention_args(prefix='ObjectLock'))
            # WON'T BE ABLE TO USE upload_file OR upload_fileobj BECAUSE THEY DON'T SUPPORT Object Lock
            _log.info("storing snapshot from %r at key %s", fpath, snapshot_key)
            self.s3.put_object(
                Bucket=self.bucket,
                Key=snapshot_key,
                Body=f,
                ContentMD5=md5_hash.aws_integrity(),
                **extra_args,
            )
            _log.info("snapshot from %r stored in S3", fpath)
            
            # Record this snapshot in the manifest
            self.manifest.add(snapshot_key)
    
    def upload_manifest(self, ):
        extra_args = dict(
            ContentType='text/plain',
        )
        extra_args.update(self._retention_args(prefix='ObjectLock'))
        with TemporaryFile() as f:
            with _sublogger('snapshot_manifest', section='manifest') as manifest_log:
                for snapshot in sorted(self.manifest):
                    manifest_log.note("%s", snapshot)
                    f.write(snapshot.encode('utf8') + b'\n')
                f.flush()
            f.seek(0)
            
            md5_hash = S3IntegrityHasher()
            FileHasher(md5_hash).consume(f, 1 << 20)
            f.seek(0)
            # WON'T BE ABLE TO USE upload_file OR upload_fileobj BECAUSE THEY DON'T SUPPORT Object Lock
            manifest_key = self.manifest_prefix + self._hostify("snapshot_manifest.txt")
            _log.info("uploading snapshots manifest to s3://%s/%s", self.bucket, manifest_key)
            self.s3.put_object(
                Bucket=self.bucket,
                Key=manifest_key,
                Body=f,
                ContentMD5=md5_hash.aws_integrity(),
                **extra_args,
            )
            _log.info("snapshots manifest stored in S3")
    
    @classmethod
    def extract_restore_cmd(cls, snapshotter_output: str) -> Optional[str]:
        result = None
        for line in snapshotter_output.splitlines():
            parts = re.match(r'\s*::restore-through::\s*(\S.*)', line)
            if parts is None:
                continue
            
            result = parts[1]
        return result
