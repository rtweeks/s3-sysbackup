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

"""Tools for building s3-sysbackup AWS resources

Many of the s3-sysbackup resources are global, so rather than outputting or
exporting from a CloudFormation template, the values are tagged onto the
IAM Role to be assumed for access to back up into the bucket.  The role is
identified because it has the path '/systems/{package_name}/' and the name
'DataBackupRole-{package_name}'.

See :class:`ServiceResourceCreator` for creation of a backup repository and
:func:`create_user` for creating a "backing-up user" account for use by
scheduled jobs.
"""

import boto3
from pathlib import Path
from uuid import uuid4
from .utils import (
    as_attr,
    namedtuple_def,
)

@namedtuple_def
class PackageParameters(list):
    def __init__(self, ):
        super().__init__('permissions_boundary_arn group_name bucket'.split())
    
    def user_creation_parameters(self, ):
        return list(
            dict(ParameterKey=k, ParameterValue=v)
            for k, v in zip(
                ('PermissionsBoundaryArn', 'Group'),
                self[:2]
            )
        )

PackageParameters.TAG_NAMES = 'ExternalUserPermissionsBoundary ExternalBackupsGroup Bucket'.split()
DEFAULT_PACKAGE_NAME = 's3-sysbackup'
INFO_TAG_PREFIX = DEFAULT_PACKAGE_NAME + ':'

@as_attr(PackageParameters, 'lookup_existing')
@classmethod
def _(cls, package_name: str = DEFAULT_PACKAGE_NAME):
    iam = boto3.resource('iam')
    target_role_name = "DataBackupRole-{}".format(package_name)
    roles = list(
        r for r in iam.roles.filter(
            PathPrefix="/systems/{}/".format(package_name)
        )
        if r.name == target_role_name
    )
    if len(roles) != 1:
        raise ValueError(
            "{!r} is not a valid s3-sysbackup package name;"
            " please look for a package name in the path of an IAM Role"
            " named 'DataBackupRole-*'".format(package_name)
        )
    role = roles[0]
    role.reload() # to get tags
    key_dict = dict(
        (i['Key'][len(INFO_TAG_PREFIX):], i['Value'])
        for i in role.tags
        if i['Key'].startswith(INFO_TAG_PREFIX)
    )
    params = list(
        key_dict.get(k)
        for k in PackageParameters.TAG_NAMES
    )
    return PackageParameters(*params)

def _read_template(template_name: str) -> str:
    template_path = Path(__file__).parent / 'cf_templates' / (template_name + '.yml')
    with template_path.open() as f:
        return f.read()

def create_user(user_name: str, package_name: str = DEFAULT_PACKAGE_NAME, *, cf_resource=None, region_name=None):
    params = PackageParameters.lookup_existing(package_name=package_name)

    cf = cf_resource or boto3.resource('cloudformation', region_name=region_name)
    return cf.create_stack(
        StackName=user_name,
        TemplateBody=_read_template('createuser'),
        Parameters=params.user_creation_parameters(),
        Capabilities=['CAPABILITY_NAMED_IAM'],
    )

class ServiceResourceCreator:
    region_name = None
    stack_name = None
    bucket_export = None
    
    def __init__(self, package_name: str = DEFAULT_PACKAGE_NAME):
        super().__init__()
        self.package_name = package_name
    
    def create_resources(self, *, cf_resource=None):
        resource_kwargs = {}
        if self.region_name is not None:
            resource_kwargs['region_name'] = self.region_name
        cf = cf_resource or boto3.resource('cloudformation', **resource_kwargs)
        
        return cf.create_stack(
            StackName=self.stack_name or self.package_name,
            TemplateBody=_read_template('resources'),
            Parameters=_make_params(
                BucketName="backups-{}".format(uuid4()),
                BucketExport=self.bucket_export,
                PackageName=self.package_name,
            ),
            Capabilities=['CAPABILITY_NAMED_IAM'],
        )

def _make_params(**kwargs):
    return list(
        dict(ParameterKey=k, ParameterValue=v)
        for k, v in kwargs.items()
        if v is not None
    )
