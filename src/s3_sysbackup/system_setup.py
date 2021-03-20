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

"""Tools for writing local-system configuration files

The :class:`ConfigWriter` helps coordinate tasks that should be completed as
a non-privileged user and those which require ``sudo`` access.
"""
import builtins
from colors import color as termstyle
from configparser import ConfigParser
import functools
import io
import itertools
import os
from pathlib import Path as PathObj
import shlex
import string
import subprocess as subp
import sys
from typing import Optional, List, Union as OneOf
import warnings
from . import resource_setup
from .utils import (
    as_attr,
    namedtuple_def,
)

import logging
_log = logging.getLogger(__name__)

Path = OneOf[str, os.PathLike] # Referencing any filesystem entry
FilePath = OneOf[str, os.PathLike] # Referencing a file entry

@namedtuple_def
class _SubprocCall(list):
    def __init__(self, ):
        super().__init__(['args', 'kwargs'])
    
    def run(self, *, capture: Optional[dict] = None):
        if capture is None:
            run_kwargs = self.kwargs
        else:
            run_kwargs = dict(self.kwargs)
            for stream in ('stdout', 'stderr'):
                if stream in capture and stream not in run_kwargs:
                    run_kwargs[stream] = capture[stream]
        
        return subp.run(self.args, **run_kwargs)
    
    def is_sudo(self):
        return self.args[0] == 'sudo'

@as_attr(_SubprocCall, '__str__')
def _(self):
    cmd_parts = list(shlex.quote(t) for t in self.args)
    
    cmd_stdin = self.kwargs.get('stdin')
    if 'input' in self.kwargs or cmd_stdin not in (None, subp.DEVNULL):
        cmd_parts.append("<(FROM-PROGRAM)")
    
    stdout = self.kwargs.get('stdout')
    if stdout is subp.DEVNULL:
        cmd_parts.append(">" + os.devnull)
    elif stdout is not None:
        cmd_parts.append(">(TO-PROGRAM)")
    
    stderr = self.kwargs.get('stderr')
    if stderr is subp.DEVNULL:
        cmd_parts.append("2>" + os.devnull)
    elif stderr is subp.STDOUT:
        cmd_parts.append("2>&1")
    elif stderr is not None:
        cmd_parts.append("2>(TO-PROGRAM)")
    
    return ' '.join(cmd_parts)

@as_attr(_SubprocCall, '__repr__')
def _(self):
    try:
        my_str = str(self)
    except Exception as e:
        my_str = "error in __str__"
    return "<{}.{}: {}>".format(
        type(self).__module__,
        type(self).__qualname__,
        my_str,
    )

def _subproc_call(*args, **kwargs):
    kwargs.setdefault('check', True)
    if 'input' not in kwargs:
        kwargs.setdefault('stdin', subp.DEVNULL)
    return _SubprocCall(list(args), kwargs)

KEY_PAIR_ATTRIBUTES = ('access_key_id', 'secret_access_key')
DEFAULT_CONF_DIR = '/etc/backup'

@namedtuple_def
def _DecryptedAccessKeyPair():
    return KEY_PAIR_ATTRIBUTES + ('source_file',)

class _SystemConfigurator:
    def configure_system(self, ui=None):
        """Run the configuration process
        
        :param ui:
            the user interface object (a :class:`ConsoleUserInterface` if
            ``None`` given) which will be used for interaction with the user
        
        The *ui* must support three methods: ``ask_for_sudo``,
        ``configure_password`` and ``run_command``.  Please see
        :class:`ConsoleUserInterface` for the call interfaces.
        """
        if ui is None:
            ui = ConsoleUserInterface()
        
        cmds = list(self.all_config_cmds())
        sudo_needed = any(cmd.is_sudo() for cmd in cmds)
        
        sudo_cmds = list(cmd for cmd in cmds if cmd.args[0] == 'sudo')
        if sudo_cmds:
            ui.ask_for_sudo(sudo_cmds)
        
        for cmd in cmds:
            if cmd.is_sudo() and '-n' not in cmd.args:
                cmd.args.insert(1, '-n')
            if isinstance(cmd, PasswordRequired):
                ui.configure_password(cmd)
            ui.run_command(cmd)

class ConfigWriter(_SystemConfigurator):
    """A tool to write the configuration files to allow a Saver to run
    
    A :class:`s3_sysbackup.saver.Saver` needs several files and directories
    with appropriate permissions.  Obtaining some of the sensitive information
    (e.g. "backing-up user" credentails) would be difficult to do in a
    super-user context.  Therefore, this class constructs a sequence of
    commands, some of which may require invocation of ``sudo``.
    
    :attr:`.conf_dir`
        Directory in which the Saver configuration is written
    
    :attr:`.role_arn`
        ARN of the IAM Role that should be assumed for writing the backup data
        to S3
    
    :attr:`.bucket`
        Name of the S3 bucket to which backup objects are to be written
    
    :attr:`.profile`
        Name of profile in the unencrypted credentials file to use for the
        credentials of the "backing-up user"
    
    :attr:`.retention_days`
        Number of days for which the uploaded backup data should be retained
        in S3
    
    :attr:`.encrypted_credentials_file`
        The file in which an encrypted version of the "backing-up user's" AWS
        credentials are stored or from which such credentials are read.
        Reading occurs if this attribute is set when :attr:`.access_key_pair`
        is ``None``; writing occurs if both these attributes are set *and* the
        target file does not exist.
        
        If this attribute is set, the ``ccrypt`` program must be available
        and a console user interface is assumed.
    
    :attr:`.access_key_pair`
        An object with ``access_key_id`` and ``secret_access_key`` attributes;
        the most likely classes are :class:`IAM.AccessKeyPair` and
        :class:`._DecryptedAccessKeyPair`.  This value can be loaded from an
        encrypted file by setting :attr:`.encrypted_credentials_file` and
        calling :meth:`.load_encrypted_user_credentials`.  Alternatively, it
        can be set by passing an :class:`IAM.User` to
        :meth:`.use_new_access_key` (though this creates a new access key for
        the IAM account).
    
    When preparing to run the commands, consider the following actions on the
    :class:`.ConfigWriter` instance:
    
    * Call :meth:`.lookup_s3_params` to set the :attr:`.bucket` and
      :attr:`.arn_role`.
    * Either:
    
        * Set :attr:`.encrypted_credentials_file` either for loading or storing
          encrypted "backing-up user" credentials.
        * Create and pass a new user to :meth:`.use_new_access_key` (if a new
          user is wanted) along with a path to a file to receive the encrypted
          "backing-up user" credentials.
    
    * Call :meth:`.configure_system` or otherwise make use of the commands
      returned from :meth:`.all_config_cmds`.
    """
    ENCRYPTED_SECTION = 'encrypted'
    CCRYPT_PROGRAM = 'ccrypt'
    
    conf_dir = DEFAULT_CONF_DIR
    role_arn = None
    bucket = None
    profile = None
    retention_days = None
    encrypted_credentials_file = None # Set this to read or write an encrypted credentials file
    credentials_file = 'aws_credentials'
    access_key_pair = None # like an IAM.AccessKeyPair resource
    
    @property
    def conf_file(self):
        return os.path.join(self.conf_dir, 'conf')
    
    @property
    def credentials_fpath(self):
        return os.path.join(self.conf_dir, self.credentials_file)
    
    def lookup_s3_params(self, package_name: str = resource_setup.DEFAULT_PACKAGE_NAME):
        """Set :attr:`.bucket` and :attr:`.role_arn` from AWS data
        
        Looks the existing :class:`.resource_setup.PackageParameters` for
        *package_name*.
        """
        params = resource_setup.PackageParameters.lookup_existing(package_name)
        self.bucket = params.bucket
        self.role_arn = (
            params.permissions_boundary_arn[:26] +
            "role/systems/{package}/DataBackupRole-{package}".format(
                package=package_name
            )
        )
    
    def use_new_access_key(self, user, encrypted_credentials_file: Optional[FilePath]):
        """Convenience method to create an AWS key pair for use via a credentials file
        
        :param user:
            object representing an IAM User
        :type user: IAM.User
        :param encrypted_credentials_file:
            where the password-encrypted credentials get stored for
            installation on other systems
        
        This method is useful for accepting a :class:`IAM.User` object --
        conceptually, the target IAM User for the backup system to run under --
        for writing the credential file for the system.  As a given user can
        only have two access keys, it is preferable to use this function on
        one machine, then copy the credentials securely to other machines that
        want to participate in the backup system.  (See
        :attr:`.encrypted_credentials_file`.)
        
        This method is a handy recipient of the output of
        :func:`s3_sysbackup.resource_setup.create_user`::
        
            import os.path
            from s3_sysbackup.resource_setup import create_user
            from s3_sysbackup.system_setup import ConfigWriter
            
            cwriter = ConfigWriter()
            cwriter.encrypted_credentials_file = os.path.expandpath('~/backup-creds.conf.cpt')
            cwriter.use_new_access_key(create_user(input("New backup user name: ")))
            ...
            cwriter.configure_system_cli()
        """
        if self.access_key_pair:
            warnings.warn("Already generated access key pair")
            return
        if encrypted_credentials_file is not None:
            # See if the ccrypt program is available for encrypting the credentials
            subp.run([self.CCRYPT_PROGRAM, '--version'], stdout=subp.DEVNULL)
            
            # See if the encrypted credentials file already exists
            if os.path.exists(encrypted_credentials_file):
                raise Exception("Encrypted credentials file {!r} already exists".format(
                    os.fspath(encrypted_credentials_file)
                ))
            
            self.encrypted_credentials_file = encrypted_credentials_file
            
        self.access_key_pair = user.create_access_key_pair()
    
    def write_credentials_cmds(self, ):
        yield _subproc_call(
            *_sudo_install_file_cmd(self.credentials_fpath, mode=0o640, group='backup'),
            input=self._credentials_file_content().encode('utf8'),
        )
    
    def write_encrypted_user_credentials(self, ):
        if self.encrypted_credentials_file is None:
            return
        
        with open(self.encrypted_credentials_file, 'wb') as outf:
            yield _subproc_call(
                self.CCRYPT_PROGRAM, '--encrypt',
                input=self._credentials_file_content(
                    section=self.ENCRYPTED_SECTION
                ).encode('utf8'),
                stdout=outf,
            )
    
    def load_encrypted_user_credentials(self, ):
        loader = _EncryptedUserCredentialLoader(self)
        loader.run()
    
    def write_conf_cmds(self, ):
        config = ConfigParser()
        config.read(os.fspath(self.conf_file))
        config.should_write = False
        
        def get_value(section, name):
            if config.has_section(section):
                return config[section].get(name)
        
        def set_value(section, name, value):
            if not config.has_section(section):
                config.add_section(section)
            config[section][name] = str(value)
            config.should_write = True
        
        def pop_value(section, name):
            if config.has_section(section):
                return config[section].pop(name, None)
        
        if self.access_key_pair is not None and get_value('aws', 'credentials_file') != self.credentials_fpath:
            set_value('aws', 'credentials_file', self.credentials_fpath)
        if self.role_arn is not None:
            set_value('aws', 'role_arn', self.role_arn)
        if self.profile is False:
            pop_value('aws', 'profile')
        elif self.profile is not None:
            set_value('aws', 'profile', self.profile)
        
        if self.bucket is not None:
            set_value('s3', 'bucket', self.bucket)
        
        if self.retention_days is not None:
            set_value('content', 'days_retained', self.retention_days)
        
        if config.should_write:
            yield _subproc_call(
                *_sudo_install_file_cmd(self.conf_file),
                input=_config_text(config).encode('utf8'),
            )
        
    def create_conf_subdirs_cmds(self, ):
        for subdir in ('pickers.d', 'snapshots.d'):
            yield _subproc_call(
                'sudo', 'install', '-d', os.path.join(self.conf_dir, subdir)
            )
        
    def all_config_cmds(self, ):
        """Iterate the commands to configure the present system
        
        If an :attr:`encrypted_credentials_file` is given but no
        :attr:`access_key_pair` is, this method will attempt to load the
        access key pair from the encrypted file.
        """
        yield _subproc_call(
            'sudo', 'install', '--mode=0755', '-d', self.conf_dir,
        )
        
        if self.access_key_pair is not None:
            if self.encrypted_credentials_file:
                if os.path.exists(self.encrypted_credentials_file):
                    warnings.warn("File {!r} already exists, will NOT overwrite".format(
                        self.encrypted_credentials_file
                    ))
                else:
                    # yield from self.write_encrypted_user_credentials()
                    yield _EncryptedUserCredentialWriter(self)
            yield from self.write_credentials_cmds()
        elif self.encrypted_credentials_file:
            # self.load_encrypted_user_credentials() # TODO: Turn the into a _SubprocCall-like interface and yield it
            yield _EncryptedUserCredentialLoader(self)
            yield from self.write_credentials_cmds()
        yield from self.write_conf_cmds()
        yield from self.create_conf_subdirs_cmds()
    
    def _credentials_file_content(self, *, section=None):
        if section is None:
            section = self.profile or 'default'
        cred_config = ConfigParser()
        cred_config.add_section(section)
        
        for k in KEY_PAIR_ATTRIBUTES:
            cred_config[section]['aws_' + k] = getattr(self.access_key_pair, k)
        
        return _config_text(cred_config)

class UnitsWriterDefaults:
    unit_base_name = 's3-sysbackup-archive'
    backup_window_start = '2:00'
    backup_window_length = '1h'

class UnitsWriter(_SystemConfigurator, UnitsWriterDefaults):
    UNIT_FPATH_TEMPLATE = '/etc/systemd/system/{}.{}'
    
    conf_dir = DEFAULT_CONF_DIR
    start_and_enable = True
    
    def all_config_cmds(self, ):
        yield from self.write_units_cmds()
        if self.start_and_enable:
            yield from self.start_and_enable_cmds()
        else:
            yield _subproc_call(
                'echo', "Run these commands to start and enable the service:"
            )
            yield _subproc_call(
                'echo', '    ' + '; '.join(self.start_and_enable_cmds()),
            )
    
    def write_units_cmds(self, ):
        service_template = self._read_template('archive.service')
        service_unit = service_template.substitute(
            archive_cmd=self._archive_command(),
        )
        
        timer_template = self._read_template('archive.timer')
        timer_unit = timer_template.substitute(
            window_start=self.backup_window_start,
            window_length=self.backup_window_length,
        )
        
        yield _subproc_call(
            *_sudo_install_file_cmd(
                self.UNIT_FPATH_TEMPLATE.format(self.unit_base_name, 'service'),
            ),
            input=service_unit.encode('utf8'),
        )
    
        yield _subproc_call(
            *_sudo_install_file_cmd(
                self.UNIT_FPATH_TEMPLATE.format(self.unit_base_name, 'timer'),
            ),
            input=timer_unit.encode('utf8'),
        )
        
        yield _subproc_call(
            'sudo', 'systemctl', 'daemon-reload'
        )
        
        for suffix in ('service', 'timer'):
            yield _subproc_call(
                'systemd-analyze', 'verify', self.unit_base_name + '.' + suffix,
            )
    
    def start_and_enable_cmds(self, ):
        for cmd in ('enable', 'start'):
            yield _subproc_call(
                'sudo', 'systemctl', cmd, self.unit_base_name + '.timer'
            )
    
    @classmethod
    def _read_template(cls, template_name: str) -> str:
        template_path = PathObj(__file__).parent / 'systemd_templates' / template_name
        with template_path.open() as f:
            return string.Template(f.read())
    
    def _archive_command(self, ):
        parts = [sys.executable, '-m', __package__, 'archive']
        if self.conf_dir != DEFAULT_CONF_DIR:
            parts.extend(['--conf-dir', self.conf_dir])
        return ' '.join(shlex.quote(t) for t in parts)

class MulticonfigWriter(_SystemConfigurator):
    def __init__(self, *configurators):
        super().__init__()
        self.configurators = configurators
    
    def all_config_cmds(self, ):
        return itertools.chain.from_iterable(
            c.all_config_cmds()
            for c in self.configurators
        )

def _sudo_install_file_cmd(dest: FilePath, *, mode:int = 0o644, group: str = '') -> List[str]:
    words = ['sudo', 'install', '--mode=0{:o}'.format(mode)]
    if group:
        words.append('--group={}'.format(group))
    words.append('/dev/stdin')
    words.append(os.fspath(dest))
    return words

def _config_text(cp: ConfigParser) -> str:
    content = io.StringIO()
    cp.write(content)
    return content.getvalue()

class ConsoleUserInterface:
    """The basic console captive user interface (CUI)"""
    ACCEPTED_AS_YES = ('y', 'Y', 'yes', 'YES', 'Yes')
    
    _output = staticmethod(print)
    _input = staticmethod(input)
    
    def ask_for_sudo(self, commands: List[_SubprocCall]):
        """Ask the user for permission to run commands as root
        
        **CALLED BY :meth:`.ConfigWriter.configure_system`**
        
        Determines if the process is already running in a context with the
        capability to run ``sudo`` commands, then either prompts the user for
        a yes/no answer (if ``sudo`` already authorized) or a password (if
        not).
        """
        self._output(self.Style.interaction_title(
            "Commands Requiring root Access"
        ))
        self._output()
        for cmd in commands:
            # self._output("  $ " + str(cmd))
            self._output(self.Style.command(str(cmd)))
        self._output()
        
        # Test if console already has sudo
        need_sudo = subp.run(
            ['sudo', '-vn'],
            stdin=subp.DEVNULL,
            stderr=subp.DEVNULL,
        ).returncode
        
        prompt_style = self.Style.security_prompt
        if need_sudo:
            subp.run(
                ['sudo', '-v', "--prompt={} ".format(
                    prompt_style("Enter password for %p to execute:")
                )],
                check=True,
            )
        elif self._input(prompt_style("Execute (y/n)? ")).strip() not in self.ACCEPTED_AS_YES:
            raise Exception("User canceled")
    
    def configure_password(self, cmd: 'PasswordRequired'):
        """Provide the password for a :class:`PasswordRequired` step
        
        **CALLED BY :meth:`.ConfigWriter.configure_system`**
        
        This method may take any action necessary to query the user for and
        provide *cmd* with the password needed for the step.
        :class:`PasswordRequired` instances typically default to querying
        for a password on the console if no other provision to present them
        a password is made.
        """
        pass # Nah, we'll let the program get the password from the console
    
    def run_command(self, cmd: _SubprocCall):
        """Execute the given command
        
        **CALLED BY :meth:`.ConfigWriter.configure_system`**
        
        """
        self._output(self.Style.command(str(cmd)))
        
        # If there was anything better to connect STDOUT and STDERR to,
        # *capture=* could be passed in this call
        cmd.run()
    
    class Style:
        @classmethod
        def interaction_title(cls, s: str) -> str:
            return termstyle(
                " {} ".format(s).center(78, '='),
                fg='white', bg='blue', style='bold'
            )
        
        @classmethod
        def command(cls, cmd_str: str) -> str:
            return termstyle("\u2023 " + cmd_str, fg='blue', style='bold')
        
        @classmethod
        def security_prompt(cls, s: str) -> str:
            return termstyle(s, fg='yellow', style='bold')

class PasswordRequired:
    password = None # Put the password here if command line input is not desirable

def check_systemd_calendar_spec(s: str) -> str:
    proc_result = _subproc_call(
        'systemd-analyze', 'calendar', s,
        stdout=subp.PIPE,
    ).run()
    return proc_result.stdout

class _CcryptCommand(PasswordRequired):
    @classmethod
    def _passing_password_in_env(cls, cmd, password):
        if password is None:
            return
        
        envvar = "PASSWORD_" + secrets.token_hex(16)
        cmd.args.extend(['-E', envvar])
        new_env = dict(cmd.kwargs.get('env', os.environ))
        new_env[envvar] = password
        cmd.kwargs['env'] = new_env
    
    def is_sudo(self):
        return False
    
    def __str__(self, ):
        return str(self._create_ccrypt_invocation())
    
    __repr__ = _SubprocCall.__repr__

class _EncryptedUserCredentialLoader(_CcryptCommand):
    def __init__(self, config_writer: ConfigWriter):
        super().__init__()
        self._writer = config_writer
    
    @property
    def args(self):
        return self._create_ccrypt_invocation().args
    
    def run(self, *, capture=None):
        if capture is None:
            capture = {}
        
        writer = self._writer
        with open(writer.encrypted_credentials_file, 'rb') as inf:
            cmd = self._create_ccrypt_invocation(inf)
            if 'stderr' in capture and 'stderr' not in cmd.kwargs:
                cmd.kwargs['stderr'] = capture['stderr']
            try:
                cmd_result = cmd.run()
            except subp.CalledProcessError as e:
                _log.warning("Unable to read encrypted backing-up user credential file: %s", e, exc_info=True)
            else:
                cred_config = ConfigParser()
                cred_config.read_string(cmd_result.stdout.decode('utf8'))
                writer.access_key_pair = _DecryptedAccessKeyPair(*(
                    cred_config[writer.ENCRYPTED_SECTION]['aws_' + k]
                    for k in KEY_PAIR_ATTRIBUTES
                ), inf.name)
                del writer.encrypted_credentials_file
    
    def _create_ccrypt_invocation(self, input=subp.PIPE):
        writer = self._writer
        password = self.password
        result = _subproc_call(
            writer.CCRYPT_PROGRAM, '--decrypt',
            stdin=input,
            stdout=subp.PIPE,
        )
        
        self._passing_password_in_env(result, password)
        
        return result

class _EncryptedUserCredentialWriter(_CcryptCommand):
    def __init__(self, config_writer: ConfigWriter):
        super().__init__()
        self._writer = config_writer
    
    @property
    def args(self):
        return self._create_ccrypt_invocation().args
    
    def run(self, *, capture=None):
        if capture is None:
            capture = {}
        
        writer = self._writer
        with open(writer.encrypted_credentials_file, 'wb') as outf:
            cmd = self._create_ccrypt_invocation(outf)
            if 'stderr' in capture and 'stderr' not in cmd.kwargs:
                cmd.kwargs['stderr'] = capture['stderr']
            try:
                cmd_result = cmd.run()
            except subp.CalledProcessError as e:
                _log.warning("Unable to write encrypted backing-up user credential file: %s", e, exc_info=True)
    
    def _create_ccrypt_invocation(self, dest=subp.PIPE):
        writer = self._writer
        password = self.password
        
        if isinstance(writer, type):
            content = "fake data"
        else:
            content = writer._credentials_file_content(
                section=writer.ENCRYPTED_SECTION,
            )
        
        result = _subproc_call(
            writer.CCRYPT_PROGRAM, '--encrypt',
            input=content.encode('utf8'),
            stdout=dest,
        )
        self._passing_password_in_env(result, password)
        
        return result
