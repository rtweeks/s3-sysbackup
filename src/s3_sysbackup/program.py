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

import argparse
import functools
import os
from pathlib import Path
import sys
from textwrap import dedent

from .system_setup import DEFAULT_CONF_DIR
from .utils import value

USE_SYS_ARGV = object()

def main(args=USE_SYS_ARGV, *, exit_error=SystemExit):
    if args is USE_SYS_ARGV:
        args = sys.argv[1:]
    
    if isinstance(args, (list, tuple)):
        args = get_argparser().parse_args(args)
    
    handler = (
        getattr(args, 'handler', None)
        or _MainProgramHelp(None, None).as_error
    )
    try:
        handler(args)
    except InvalidCommandLine as e:
        print(e.args[0], file=sys.stderr)
        raise exit_error(2)
    except Exception as e:
        if 'trace' in os.environ.get('ON_ERROR', '').split(','):
            raise
        print("ERROR: ", e)
        raise exit_error(1)

def get_argparser():
    parser = argparse.ArgumentParser(
        add_help=False
    )
    subparsers = parser.add_subparsers()
    
    parser.add_argument('-h', '--help', action=_MainProgramHelp,
                        help="Show this help message and exit")
    
    
    for subc in _subcommands:
        subc_parser = subc.argparser
        subparser = subparsers.add_parser(
            subc.command,
            parents=[subc_parser],
            description=subc_parser.description,
            epilog=subc_parser.epilog,
        )
        subparser.set_defaults(handler=subc)
    
    return parser

class _MainProgramHelp(argparse.Action):
    def __init__(self, option_strings, dest, *, nargs=None, **kwargs):
        if nargs not in (None, 0):
            raise ValueError("'nargs' not allowed")
        super().__init__(option_strings, dest, nargs=0, **kwargs)
    
    @property
    def as_error(self):
        return functools.partial(self, as_error=True)
    
    def __call__(self, *args, as_error=False, **kwargs):
        lines = [
            "Usage:",
            "    %(prog)s SUBCOMMAND [ -h | --help ] ...",
            "    %(prog)s ( -h | --help )",
            "",
            "Subcommands:",
            *("    " + l for l in self.subcommand_help_lines()),
            "",
            "Optional arguments:",
            "    -h, --help    Show this help message",
        ]
        print(
            '\n'.join(lines) % dict(prog=Path(sys.argv[0]).name),
            file=sys.stderr if as_error else sys.stdout
        )
        raise SystemExit(2 if as_error else 0)
    
    def subcommand_help_lines(self, ):
        command_cols = max(len(h.command) for h in _subcommands)
        for handler in sorted(_subcommands, key=lambda h: h.command):
            yield "{}    {}".format(
                handler.command.rjust(command_cols),
                (handler.__doc__ or '').split('\n')[0].strip(),
            )

_subcommands = []
def _subcommand(fn=None, **kwargs):
    if fn is None:
        return functools.partial(_subcommand, **kwargs)
    
    fn.command = kwargs.get('command') or fn.__name__.replace('_', '-')
    fn.argparser = argparse.ArgumentParser(add_help=False)
    _subcommands.append(fn)
    return fn

class _CommonArgs:
    @classmethod
    def package_name(cls, parser):
        parser.add_argument(
            '--package-name', action='store',
            help="Explicit package name for S3 resource group",
        )

@_subcommand
def create_resources(args):
    """Create resources in AWS"""
    from .resource_setup import ServiceResourceCreator
    
    tool = ServiceResourceCreator(**_ProgOptKwargs(args)
        .incorporate('package_name')
    )
    tool.region_name = args.region_name
    tool.stack_name = args.stack_name
    tool.bucket_export = args.bucket_export
    tool.create_resources()
with value(create_resources.argparser) as parser:
    parser.add_argument(
        '--cf-region', dest='region_name', action='store',
        help="AWS region name in which to create the CloudFormation stack",
    )
    _CommonArgs.package_name(parser)
    parser.add_argument(
        '--stack-name', action='store',
        help="Explicit stack name for CloudFormation stack"
            " (defaults to the package name)",
    )
    parser.add_argument(
        '--export', dest='bucket_export', action='store',
        help="Explicit export name with which to export the created bucket name",
    )

@_subcommand
def write_config(args):
    """Write an archiving configuration for the local system"""
    from .resource_setup import create_user
    from .system_setup import ConfigWriter
    
    tool = ConfigWriter()
    tool.lookup_s3_params(**_ProgOptKwargs(args)
        .incorporate('package_name')
    )
    if args.new_user:
        if not args.creds_file and args.save_new_credentials:
            raise InvalidCommandLine(
                "Either specify an '--creds-file' or '--no-creds-file'"
            )
        tool.use_new_access_key(
            create_user(args.new_user, package_name=args.package_name),
            args.creds_file if args.save_new_credentials else None,
        )
    elif not args.creds_file:
        raise InvalidCommandLine(
            "Specify either '--user', '--creds-file', or both"
        )
        tool.encrypted_credentials_file = args.creds_file
    for k, v in _ProgOptKwargs(args).incorporate(
        'conf_dir',
        'profile',
        'retention_days',
    ).items():
        setattr(tool, k, v)
    tool.configure_system()
with value(write_config.argparser) as parser:
    parser.add_argument(
        '--conf-dir', action='store', default=DEFAULT_CONF_DIR,
        help="Explicitly specify where the local system configuration is created",
    )
    _CommonArgs.package_name(parser)
    parser.add_argument(
        '-u', '--user', metavar='IAM-USER', action='store', dest='new_user',
        help="Create a new AWS IAM user IAM-USER to archive data",
    )
    parser.add_argument(
        '--creds-file', metavar='FPATH', action='store',
        help="Path to file for encrypted IAM user credentials",
    )
    parser.add_argument(
        '--no-creds-file', action='store_false',
        dest='save_new_credentials',
        help="Do not save encrypted version of newly-created IAM user's"
            " credentials",
    )
    parser.epilog = dedent("""
        You can use '--creds-file' to supply a path either *from which* to load
        the IAM user account credentials or *to which* new IAM user account
        will be saved; which of the two occurs depends on the presence of
        '--user': saving if it is given, loading if not.
    """)

class _ProgOptKwargs(dict):
    def __init__(self, program_args):
        super().__init__()
        self.program_args = program_args
    
    def incorporate(self, *opt_names):
        for opt_name in opt_names:
            opt_value = getattr(self.program_args, opt_name)
            if opt_value is not None:
                self[opt_name] = opt_value
        return self

class InvalidCommandLine(Exception):
    """Raised when the command line is invalid"""

if __name__ == '__main__':
    main(sys.argv[1:])
