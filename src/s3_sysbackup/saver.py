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
from configparser import ConfigParser
from datetime import datetime, timedelta
from getpass import getuser
import gzip
import json
import os
import os.path
from pprint import pformat
import socket
import subprocess as subp
from tempfile import TemporaryFile

from .quilting import Quilter, TargetFileError
from .snapshots import Snapshotter
from .utils import (
    FileHasher,
    S3IntegrityHasher,
    is_aws_error as _is_aws_error,
)

import logging
_log = logging.getLogger(__name__)

class Saver:
    """Tool for saving backups according to configs in /etc/backup
    
    Access to S3
    ------------
    
    There are several ways to set up the S3 bucket targeted for backup (given
    in descending order of precedence):
    
    * Set :attr:`.bucket` on the instance before calling :meth:`.load_config`
    * Give the bucket name as the ``bucket`` setting in the ``[s3]`` section of
      the config file
    * A bucket name exported from a CloudFormation stack
    * Export the bucket name as the export named according to the ``export``
      setting in the ``cloudformation`` section of the config file from a
      CloudFormation stack (see CloudFormation below)
    * Export the bucket name as ``backup-bucket`` from a CloudFormation stack
      (see CloudFormation below)
    
    
    CloudFormation
    --------------
    
    This backup system can pick up the name of the destination bucket for
    backups from a CloudFormation stack export.  CloudFormation is a regional
    service, so a region must be established in order to obtain the export, and
    this may be done in a few ways:
    
    * Specifying a ``region`` setting in the ``[cloudformation]`` section of
      the config file
    * Specifying an AWS profile name in the ``AWS_PROFILE`` environment
      variable, where the named profile has a default region
    * Specifying a ``profile`` setting in the ``[aws]`` section naming an AWS
      profile which has a default region
    * Giving the default AWS profile a default region
    
    The name of the export consulted is:
    
    * The name specified in the ``export`` setting of the ``[cloudformation]``
      section of the config file, if given
    * ``backup-bucket`` otherwise
    
    
    Sources
    -------
    
    Sources come in two flavors: snapshotters and pickers.  Snapshotters are
    programs that write content to the file descriptor whose number is passed
    as the first argument; they can dynamically generate files to be backed
    up, which is good for database backups.  Pickers identify file paths on
    the system that should be backed up, which might not change.  Pickers are
    more cost-efficient in AWS (as they only transmit and store the content of
    the file *one* time, unless the content changes) but they cannot handle
    dynamically generated backup content.
    
    Snapshotters are configured in ``/etc/backup/snapshots.d``.  The files
    must be in that directory (not a subdirectory) and executable (symlinks
    are acceptable).  Each snapshotter program will be called with a single
    program argument giving the file descriptor number (as a decimal string)
    to which it should write its snapshot.  Output written by the snapshotter
    to STDOUT will be saved as metadata ``backup-output`` on the S3 object (up
    to capacity limits).  A line in the output with the special format
    ``::restore-through:: CMD`` (where ``CMD`` is some command in shell
    notation) will save that ``CMD`` as the metadata entry ``restore-through``.
    The intent is that, if the content of the object is piped into ``CMD``, the
    snapshot would be restored in the system.
    
    The content identified by pickers is examined to determine if ``gzip`` can
    effectively reduce the storage space required and, if so, it is applied.
    This is noted in the S3 object by setting the ``storage-encoding`` metadata
    to ``gzip``.
    
    
    Manifests
    ---------
    
    Both snapshotter and picker systems contribute manifest data which is
    combined into a manifest file uploaded to S3 for the run.  The snapshotter
    system includes just the keys within the S3 bucket of the objects it
    uploaded (where instructions for restoring may be present on the objects in
    the ``restore-through`` metadata), while the picker system includes a list
    of filetree entries.
    
    
    Picker Manifest Entries
    -----------------------
    
    Each entry has a ``typ`` field -- which is either ``d`` for directory,
    ``l`` for symlink, of ``f`` for file (separate entries for hardlinks to
    the same file) -- a ``path`` field giving the full path of the entry,
    and ``o`` and ``g`` fields giving owner and group for the entry.  They are
    arranged in ascending order (by default Python string sorting) of ``path``.
    
    Directory
    .........
    
    Directory entries have either an ``acl`` field or a ``mode`` field.
    Whichever is present should be applied to the directory for restoration.
    
    Symlink
    .......
    
    Symlink entries have a ``tgt`` field giving the symlink's target path.
    
    File
    ....
    
    File entries are the most complicated.  Like directory entries, they have
    an ``acl`` or a ``mode`` for the file's permissions, a ``dat`` field giving
    the key within the bucket to the S3 object with the file's contents, and
    an ``id`` field, which has a common value for all files that are hardlinked
    to the same inode on the same device.
    
    When restoring picker files, it is important to keep a mapping from the
    ``id`` of file entries to the first path at which that file object was
    restored; if the same ``id`` is later encountered, create a hard link to
    that first path at the new path.
    
    Because Linux does not strongly support mandatory file locks and because
    a partially faulty backup is better than no backup at all, an advisory
    read lock is attempted on the file at the time it is copied for backup.
    If the read lock timeout expires before the file can be locked, the backup
    copy continues anyway with a warning and a notation of ``unlocked-copy``
    under the ``w`` key in the manifest entry.
    """
    bucket = None
    
    def __init__(self, config_dir=None):
        super().__init__()
        if config_dir is None:
            self.config_dir = '/etc/backup'
        else:
            self.config_dir = config_dir
    
    def load_config(self):
        config = ConfigParser()
        config.read(os.path.join(self.config_dir, 'conf'))
        
        session_kwargs = {}
        if 'AWS_PROFILE' in os.environ:
            session_kwargs.setdefault('profile_name', os.environ['AWS_PROFILE'])
        if 'profile' in config['aws']:
            session_kwargs.setdefault('profile_name', config['aws']['profile'])
        
        if 'credentials_file' in config['aws']:
            self.aws_session = self._session_from_credentials(
                config['aws']['credentials_file'],
                session_kwargs.get('profile_name', 'default'),
                role_arn=config['aws'].get('role_arn'),
            )
        else:
            self.aws_session = boto3.Session(**session_kwargs)
        
        if self.bucket is None and 'bucket' in config['s3']:
            self.bucket = config['s3']['bucket']
        if self.bucket is None:
            cf_client_kwargs = {}
            if 'region' in config['cloudformation']:
                cf_client_kwargs.update(region_name=config['cloudformation']['region'])
            cf = self.aws_session.client('cloudformation', **cf_client_kwargs)
            
            export_name = config['cloudformation'].get('export', 'backup-bucket')
            list_exports_kwargs = {}
            while list_exports_kwargs.get('NextToken', False) is not None:
                response = cf.list_exports(**list_exports_kwargs)
                list_exports_kwargs.update(NextToken=response.get('NextToken'))
                for export in response['Exports']:
                    if export['Name'] != export_name:
                        continue
                    
                    self.bucket = export['Value']
                    break
        
        self.retention_period = timedelta(
            days=config['content'].getint('days_retained', 14)
        )
        self.lock_timeout = config['content'].getfloat('lock_timeout', 2)
        
        if self.bucket is None:
            raise Exception("no S3 bucket specified")
    
    def run(self, *, backup_name=None, return_tools=False):
        if backup_name is None:
            backup_name = "{}-backup".format(socket.gethostname())
        manifest_key = "manifests/{}.json".format(backup_name)
        extra_args = dict(
            ContentType='application/json',
        )
        s3 = self.aws_session.client('s3')
        facilitator_kwargs = dict(
            bucket=self.bucket,
            retention_period=self.retention_period,
            manifest_prefix='manifests/',
            s3_client=s3,
        )
        
        manifest = {}
        snapshotter = Snapshotter(key_prefix='snapshots/', **facilitator_kwargs)
        quilter = Quilter(lock_timeout=self.lock_timeout, **facilitator_kwargs)
        
        if return_tools:
            return dict(snapshotter=snapshotter, quilter=quilter)
        
        # Add a logging handler that records warnings+ into manifest
        log_accum_handler = _LogAccumHandler(manifest, 'log')
        log_accum_handler.setLevel(logging.WARNING)
        logging.root.addHandler(log_accum_handler)
        
        for fpath in self._provider_paths('snapshots.d'):
            try:
                snapshotter.record_from(fpath)
            except Exception as e:
                _log.exception("trying to record from %s", fpath)
        
        for fpath in self._provider_paths('pickers.d'):
            try:
                for line in self._program_output_lines(fpath):
                    try:
                        quilter.add(line.strip())
                    except TargetFileError as e:
                        _log.error("%s", e)
                    except Exception as  e:
                        if _is_aws_error(e, 'AccessDenied'):
                            raise
                        _log.exception("trying to pick %s", line.strip())
            except Exception as e:
                _log.exception("trying to pick from %s", fpath)
                if _is_aws_error(e, 'AccessDenied'):
                    break
        
        logging.root.removeHandler(log_accum_handler)
        
        try:
            manifest.update(
                content=list(
                    quilter.get_manifest_jsonl_lines(as_str=False)
                ),
                snapshots=list(snapshotter.manifest),
            )
            extra_args.update(
                ObjectLockMode='GOVERNANCE',
                ObjectLockRetainUntilDate=datetime.now() + self.retention_period
            )
            with TemporaryFile() as f:
                f.write(json.dumps(manifest).encode('ascii'))
                f.seek(0)
                md5_hash = S3IntegrityHasher()
                FileHasher(md5_hash).consume(f, 1 << 20)
                f.seek(0)
                s3.put_object(
                    Bucket=self.bucket,
                    Key=manifest_key,
                    Body=f,
                    ContentMD5=md5_hash.aws_integrity(),
                    **extra_args,
                )
        except Exception as e:
            _log.error('upload of unified manifest failed; attempting piecewise manifest upload')
            
            try:
                snapshotter.upload_manifest()
            except Exception:
                _log.exception('while handling Saver manifest upload')
            
            try:
                quilter.upload_manifest()
            except Exception:
                _log.exception('while handling Saver manifest upload')
            
            raise e
        else:
            if _log.isEnabledFor(logging.DEBUG):
                _log.debug(("manifest:\n" + pformat(manifest)).replace("\n", "\n    "))
    
    def _provider_paths(self, subdir):
        """Iterate over executable non-directories in subdir of /etc/backup"""
        top_dir = "/etc/backup/" + subdir
        for entry in os.listdir(top_dir):
            path = os.path.join(top_dir, entry)
            if os.path.isdir(path):
                continue
            if not os.access(path, os.X_OK):
                continue
            yield path
    
    def _program_output_lines(self, fpath):
        prog = subp.Popen([fpath], stdin=subp.DEVNULL, stdout=subp.PIPE, encoding='utf8')
        yield from prog.stdout
        try:
            prog.wait(0.2)
        except subp.TimeoutExpired:
            _log.error("timed out waiting for %s to exit", fpath)
        else:
            if prog.returncode != 0:
                _log.error("return code %d from %s", prog.returncode, fpath)
    
    def _session_from_credentials(self, cred_fpath, profile_name, *, role_arn=None, region_name=None):
        creds = ConfigParser()
        creds.read(cred_fpath)
        
        profile = creds[profile_name]
        role_creds = dict(
            (k, profile[k])
            for k in ('aws_access_key_id', 'aws_secret_access_key')
        )
        
        if role_arn is not None:
            sts = boto3.client('sts', **role_creds)
            role_assumption = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='{user}@{host}'.format(
                    host=socket.gethostname(),
                    user=getuser(),
                )
            )
            role_creds = tuple(
                role_assumption['Credentials'][k]
                for k in ('AccessKeyId', 'SecretAccessKey', 'SessionToken')
            )
            role_creds = dict(zip(
                ('aws_access_key_id', 'aws_secret_access_key', 'aws_session_token'),
                role_creds
            ))
        if region_name is not None:
            role_creds['region_name'] = region_name
        
        return boto3.Session(**role_creds)

class _LogAccumHandler(logging.Handler):
    def __init__(self, manifest, key):
        super().__init__()
        self.manifest = manifest
        self.key = str(key)
    
    def emit(self, record):
        if isinstance(record.msg, str):
            message = record.msg % record.args
        else:
            message = str(record.msg)
        
        self.manifest.setdefault(self.key, []).append(dict(
            at=record.asctime,
            level=record.levelname,
            logger=record.name,
            message=message,
        ))
