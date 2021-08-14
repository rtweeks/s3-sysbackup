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

import boto3
from contextlib import ExitStack, closing as block_closing
from datetime import datetime, timezone
import gzip
from itertools import count as Counter
import json
import os.path
import re
import shlex
import shutil
import socket
import sys
import tempfile
from typing import Iterable, Optional, Union as OneOf

from . import resource_setup
from .system_setup import ConsoleUserInterface, _subproc_call
from .utils import namedtuple_def

import logging
_log = logging.getLogger(__name__)

INVALID_SESSION_NAME_PATTERN = re.compile(r'[^a-zA-Z0-9=,.-]')
MANIFEST_PATTERN = re.compile(r'([^/]+).json$')

class Restorer:
    """Tool for restoring data backed up to S3
    """
    use_mfa: OneOf[bool, str] = False
    restore_content = True
    pull_snapshots = True
    restore_snapshots = True
    
    def __init__(
        self,
        backup_name: Optional[str] = None,
        *,
        aws_account: OneOf[None, str, int] = None,
        package_name: Optional[str] = None,
        ui = None,
    ):
        super().__init__()
        self.backup_name = backup_name
        self.aws_account = aws_account
        self.package_name = package_name or resource_setup.DEFAULT_PACKAGE_NAME
        self.ui = ConsoleUserInterface() if ui is None else ui
    
    def find_bucket(self, ):
        if hasattr(self, 'bucket'):
            return
        
        # Look for bucket name exported from stack
        try:
            region, export_name = self.bucket_export
        except AttributeError as e:
            raise Exception("Expected bucket_export to be defined") from e
        
        self.assume_restore_role()
        
        cf = boto3.Session(**self.cred).client('cloudformation', region_name=region)
        list_exports_kwargs = {}
        while list_exports_kwargs.get('NextToken', False) is not None:
            response = cf.list_exports(**list_exports_kwargs)
            list_exports_kwargs.update(NextToken=response.get('NextToken'))
            for export in response['Exports']:
                if export['Name'] != export_name:
                    continue
                
                self.bucket = export['Value']
                return
        
        raise NotImplementedError
    
    def get_backups(self,) -> Iterable[str]:
        self.assume_restore_role()
        
        s3 = boto3.Session(**self.cred).resource('s3')
        b = s3.Bucket(self.bucket)
        prefix = 'manifests/'
        for entry in b.objects.filter(Prefix=prefix):
            m = MANIFEST_PATTERN.match(entry.key[len(prefix):])
            if not m:
                continue
            yield m.group(1)
    
    def run(self, ):
        if self.backup_name is None:
            self.backup_name = self.ui.choose(
                "Backup to Restore",
                self.get_backups(),
            )
        
        self.assume_restore_role()
        s3 = boto3.Session(**self.cred).resource('s3')
        b = s3.Bucket(self.bucket)
        
        # Retrieve the manifest
        _log.info("Retrieving manifest")
        man_obj = b.Object("manifests/{}.json".format(self.backup_name))
        man_resp = man_obj.get()
        with block_closing(man_resp['Body']) as manifest_file:
            manifest = json.load(manifest_file)
        if manifest.get('snapshots'):
            _log.info("    %d snapshots to retrieve", len(manifest['snapshots']))
        if manifest.get('content'):
            _log.info("    %d content files to restore", len(manifest['content']))
        
        with ExitStack() as resource_stack:
            content_restorer = None
            if self.restore_content:
                content_restorer = resource_stack.enter_context(
                    _ContentRestorer(b, manifest['content'], ui=self.ui)
                )
                
            restore_script = None
            snapshot_explanation = []
            if self.pull_snapshots:
                snapshot_restorer = resource_stack.enter_context(
                    _SnapshotRestorer(b, manifest['snapshots'], ui=self.ui)
                )
                snapshot_restorer.pull_snapshots()
                if snapshot_restorer.restorations:
                    restore_script = snapshot_restorer.build_script()
                
                snapshot_explanation.append(
                    "Snapshot files are in {dir} (if, for example, your backup "
                    "configuration snapshots the output of 'lsblk' and you would "
                    "like to set up mounts before executing the content "
                    "restoration).".format(dir=snapshot_restorer.snapshotsdir),
                )
            
            self.ui.explain(
                "Restoring Files from Backup",
                
                "All files for restoration have been downloaded.  First, "
                "content files will be restored to their original file paths.  "
                "After that, any restorable snapshots will be restored.",
                
                *snapshot_explanation,
                
                "You will have an opportunity to examine and/or modify each "
                "restoration script before it is run.",
            )
            
            if content_restorer:
                invoke = [] if os.geteuid() == 0 else ['sudo']
                restore_content = _subproc_call(
                    *invoke, 'bash', content_restorer.shell_script.name,
                )
                self.ui.ask_for_sudo([restore_content])
                self.ui.run_command(restore_content)
            
            if restore_script:
                try:
                    if self.ui.yes_no(
                        "Restore snapshots as described in {script}".format(
                            script=restore_script,
                        )
                    ):
                        self.ui.run_command(
                            _subproc_call('bash', restore_script),
                        )
                        os.remove(restore_script)
                        restore_script = None
                finally:
                    if restore_script is not None:
                        print("Snapshot restoration script left at {script}".format(
                            script=restore_script
                        ))
    
    def assume_restore_role(self, ):
        if not hasattr(self, 'cred') or self.cred_expires < datetime.now(timezone.utc):
            session_kwargs = {}
            # TODO: Decrypt credentials if encrypted credentials were specified
            aws = boto3.Session(**session_kwargs)
            
            iam = aws.resource('iam')
            user = iam.CurrentUser()
            sts = aws.client('sts')
            
            mfa_args = {}
            mfa_device = None
            if self.use_mfa is True:
                try:
                    mfa_device = list(user.mfa_devices.all())[0]
                except IndexError as e:
                    raise Exception("User has no MFA device associated") from e
            elif self.use_mfa:
                mfa_device = self.use_mfa
            
            if mfa_device:
                mfa_args['SerialNumber'] = mfa_device
                mfa_args['TokenCode'] = self.ui.get_mfa_token_code()
            
            arn_parts = [
                'arn:aws:iam:',
                user.arn.split(':')[4] if self.aws_account is None else str(self.aws_account),
                'role/systems/{pkg}/DataRestoreRole-{pkg}'.format(
                    pkg=self.package_name,
                )
            ]
            
            response = sts.assume_role(
                RoleArn=':'.join(arn_parts),
                RoleSessionName="{}@{}".format(
                    INVALID_SESSION_NAME_PATTERN.sub(
                        '-',
                        user.user_name,
                    ),
                    socket.gethostname()
                ),
                **mfa_args,
            )
            
            self.cred = dict(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken'],
            )
            self.cred_expires = response['Credentials']['Expiration']
    

def _install_opts(content_entry):
    result = {}
    if 'o' in content_entry:
        result['o'] = content_entry['o']
    if 'g' in content_entry:
        result['g'] = content_entry['g']
    if 'mode' in content_entry:
        m = content_entry['mode']
        result['m'] = oct(m) if isinstance(m, int) else str(m)
    return result

SETFACL_ENTRY_BREAKS_PATTERN = re.compile(r'\n(?:\s*(?:#.*)?\n)*')
class _ContentRestorer:
    tempdir = None
    shell_script = None
    
    def __init__(self, bucket, content_manifest, *, ui=None):
        super().__init__()
        self.bucket = bucket
        self.content_manifest = content_manifest
        self.ui = ui or ConsoleUserInterface()
        self._item_counter = Counter(1)
        self._link_map = {}
        self._build()
    
    def __enter__(self, ):
        return self
    
    def __exit__(self, exc_type, ex, tb):
        if ex is None:
            self.close()
        else:
            if self.shell_script:
                _log.error(
                    "Content restoration script left at {}".format(
                        self.shell_script.name
                    ),
                )
            if self.tempdir:
                _log.warning(
                    "Supporting files left in {}".format(self.tempdir),
                )
    
    def close(self, ):
        if self.tempdir is not None:
            try:
                os.rmdir(self.tempdir)
            except FileNotFoundError:
                pass
            del self.tempdir
        if self.shell_script is not None:
            self.shell_script.close()
            try:
                os.remove(self.shell_script.name)
            except FileNotFoundError:
                pass
            del self.shell_script
    
    def _build(self, ):
        _log.info("Retrieving %d saved files", len(self.content_manifest))
        try:
            for entry in self.ui.visible_progress(
                self.content_manifest,
                prefix='Retrieving saved files',
            ):
                entry = dict(entry) # So we can modify it
                entry_type = entry.get('typ')
                if entry_type == 'd':
                    self._add_dir(entry)
                elif entry_type == 'f':
                    self._add_file(entry)
                elif entry_type == 'l':
                    self._add_symlink(entry)
                else:
                    _log.error(
                        "Unexpected content entry type %r for path %r",
                        entry_type,
                        entry.get('path'),
                    )
                    continue
                
                if 'acl' in entry:
                    self._add_setfacl(entry)
        finally:
            if self.shell_script:
                if self.tempdir:
                    self._script_command(
                        "rm -rf {tempdir}",
                        tempdir=self.tempdir,
                    )
                self.shell_script.flush()
    
    def _add_dir(self, entry: dict):
        install_opts = _install_opts(entry)
        
        self._script_install_command(
            '-d', entry['path'],
            opts_dict=install_opts,
        )
    
    def _add_file(self, entry: dict):
        file_id = entry['id']
        if file_id in self._link_map:
            self._script_command(
                "ln {target} {path}",
                target=shlex.quote(self._link_map[file_id]),
                path=shlex.quote(entry['path']),
            )
            entry.pop('acl', None) # So we won't do any ACL manipulation
        elif entry['dat'] is None:
            self._script_command(
                "touch {path}",
                path=shlex.quote(entry['path']),
            )
        else:
            install_opts = _install_opts(entry)
            cache = self._download_content(entry)
            if cache:
                self._link_map[file_id] = entry['path']
                self._script_install_command(
                    cache, entry['path'],
                    opts_dict=install_opts,
                )
            else:
                entry.pop('acl', None)
    
    def _add_symlink(self, entry: dict):
        self._script_command(
            "ln -s {target} {path}",
            target=shlex.quote(entry['tgt']),
            path=shlex.quote(entry['path']),
        )
        
        ownership = []
        if 'o' in entry:
            ownership.append(entry['o'])
        if 'g' in entry:
            if len(ownership) < 1:
                ownership.append('')
            ownership.append(entry['g'])
        if ownership:
            self._script_command(
                "chown -h {owner} {path}",
                path=shlex.quote(entry['path']),
                owner=':'.join(ownership),
            )
        
        # Symlink entries shouldn't have ACL data, but make sure
        entry.pop('acl', None)
    
    def _add_setfacl(self, entry: dict):
        acl = ','.join(
            acl_entry
            for acl_entry in SETFACL_ENTRY_BREAKS_PATTERN.split(entry['acl'])
            if acl_entry
        )
        self._script_command(
            "setfacl -m {acl} {path}",
            acl=shlex.quote(acl),
            path=shlex.quote(entry['path']),
        )
        
        # Handle "special behavior"
        if 'sb' in entry:
            changes = []
            if entry['sb'][0] != '-':
                changes.append('u+s')
            if entry['sb'][1] != '-':
                changes.append('g+s')
            if entry['sb'][2] != '-':
                changes.append('+t')
            
            if changes:
                self._script_command(
                    "chmod {changes} {path}",
                    changes=','.join(changes),
                    path=shlex.quote(entry['path']),
                )
    
    def _script_install_command(self, *args, opts_dict: Optional[dict] = None):
        if opts_dict is None:
            opts_dict = {}
        
        def get_words():
            yield 'install'
            for k, v in opts_dict.items():
                yield "-{} {}".format(k, shlex.quote(v))
            for a in args:
                yield shlex.quote(a)
        
        self._script_command(' '.join(get_words()))
    
    def _script_command(self, command, **kwargs):
        if self.shell_script is None:
            self.shell_script = tempfile.NamedTemporaryFile(
                mode='w+',
                prefix="datarestore-",
                delete=False,
            )
            print(
                "set -e # Exit if any command/pipeline fails",
                file=self.shell_script,
            )
        
        if kwargs:
            command = command.format(**kwargs)
        
        print(command, file=self.shell_script)
    
    def _download_content(self, entry) -> str:
        try:
            if self.tempdir is None:
                self.tempdir = tempfile.mkdtemp()
            
            dest_name = os.path.join(self.tempdir, str(next(self._item_counter)))
            s3_key = entry['dat']
            s3_obj = self.bucket.Object(s3_key)
            dl_resp = s3_obj.get(
                VersionId=entry['ver'],
            )
            with block_closing(dl_resp['Body']) as body_stream:
                content_encoding = dl_resp.get('Metadata', {}).get('storage-encoding')
                if content_encoding == 'gzip':
                    body_stream = gzip.GzipFile(fileobj=body_stream, mode='rb')
                elif content_encoding is None:
                    pass
                else:
                    self.handle_unknown_encoding(content_encoding, s3_key)
                
                with open(dest_name, 'wb') as outf:
                    shutil.copyfileobj(body_stream, outf)
            return dest_name
        except Exception as e:
            _log.exception("Failed to download %r", s3_key)

class _SnapshotRestorer:
    snapshotsdir = None
    
    def __init__(self, bucket, snapshot_names, *, ui=None):
        super().__init__()
        self.bucket = bucket
        self.snapshot_names = snapshot_names
        self.restorations = []
        self.ui = ui or ConsoleUserInterface()
    
    def __enter__(self, ):
        return self
    
    def __exit__(self, exc_type, ex, tb):
        if ex is None:
            self.close()
        else:
            if self.snapshotsdir is not None:
                _log.warning("Snapshots left in {path}".format(
                    path=self.snapshotsdir
                ))
    
    def close(self):
        if self.snapshotsdir is not None:
            try:
                if os.listdir(self.snapshotsdir):
                    _log.warning("Not all snapshots were restored")
                else:
                    os.rmdir(self.snapshotsdir)
            except FileNotFoundError:
                pass
    
    def pull_snapshots(self, ):
        if self.snapshotsdir is None:
            self.snapshotsdir = os.path.join(os.getcwd(), 'snapshots')
        
        if not os.path.exists(self.snapshotsdir):
            os.mkdir(self.snapshotsdir)
        
        _log.info("Retrieving %d snapshots", len(self.snapshot_names))
        for ss_name in self.ui.visible_progress(
            sorted(self.snapshot_names),
            prefix='Retrieving snapshots',
        ):
            ss_obj = self.bucket.Object(ss_name)
            dest_path = os.path.join(
                self.snapshotsdir,
                ss_name.rpartition('/')[2]
            )
            ss_get_resp = ss_obj.get()
            with block_closing(ss_get_resp['Body']) as snapshot_file, \
                open(dest_path, 'wb') as dest_file:
                
                shutil.copyfileobj(snapshot_file, dest_file)
            
            restore_cmd = ss_get_resp.get('Metadata', {}).get('restore-through')
            if restore_cmd:
                self.restorations.append(
                    _RestorableSnapshot(dest_path, restore_cmd)
                )
    
    def build_script(self, ) -> str:
        script_file = tempfile.NamedTemporaryFile(
            mode='w+',
            prefix="snapshotrestore-",
            delete=False,
        )
        def add_cmd(*ss: Iterable[str], **kwargs):
            for s in ss:
                if kwargs:
                    s = s.format(**kwargs)
                print(s, file=script_file)
        def add_space():
            add_cmd('')
        
        add_cmd("#!/bin/false")
        add_space()
        if os.path.isabs(self.snapshotsdir):
            add_cmd("# This script should be executed with bash")
        else:
            add_cmd(
                "# This script should be executed with bash and expects to run",
                "# from {dir}",
                dir=shlex.quote(os.getcwd()),
            )
        add_space()
        
        restored_tag = '-RESTORED'
        for snapshot in self.restorations:
            cmd_template = "cat {src} | {cmd} 2>&1"
            if snapshot.restore_requires_sudo():
                cmd_template = "sudo -v && {{ " + cmd_template + "; }}"
            cmd_template = "{{ " + cmd_template + "; }} && mv {src}{{," + restored_tag + "}}"
            add_cmd(
                cmd_template,
                src=shlex.quote(snapshot.file),
                cmd=snapshot.restore_cmd,
            )
        
        add_space()
        add_cmd("read -p \"Delete restored snapshots (y/n)? \" -n 1 -r")
        add_cmd("echo; if [[ $REPLY =~ ^[Yy]$ ]]; then")
        add_cmd(
            "    rm {dir}/*{tag}",
            dir=shlex.quote(self.snapshotsdir),
            tag=restored_tag,
        )
        add_cmd("fi")
        add_cmd(
            "if [ -z \"$(ls -A {dir})\" ]; then rm -r {dir}; fi",
            dir=shlex.quote(self.snapshotsdir),
        )
        
        return script_file.name

@namedtuple_def
class _RestorableSnapshot(list):
    def __init__(self, ):
        super().__init__(['file', 'restore_cmd'])
    
    def restore_requires_sudo(self, ):
        return self.restore_cmd is not None and 'sudo' in self.restore_cmd
