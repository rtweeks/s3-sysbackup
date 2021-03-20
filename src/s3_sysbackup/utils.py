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

from base64 import b64encode
import boto3 # package boto3
from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime, timedelta
import functools
import hashlib
import inspect
import socket
from typing import Optional

import logging
_log = logging.getLogger(__name__)

# This is a function decorator -- keep it early in the file
def _debug_log(fn=None, **kwargs):
    if kwargs and fn is None:
        return functools.partial(_debug_log, **kwargs)
    
    static_fn_repr = repr(fn)
    if 'logger' in kwargs:
        log = kwargs['logger']
    else:
        log = logging.getLogger(fn.__module__)
    
    if 'child' in kwargs:
        log = log.getChild(kwargs['child'])
    
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if log.isEnabledFor(logging.DEBUG):
            call_arg_reprs = []
            call_arg_reprs.extend(repr(a) for a in args)
            call_arg_reprs.extend("{}={!r}".format(k, v) for k, v in kwargs.items())
            call_repr = "{}({})".format(fn.__qualname__, ', '.join(call_arg_reprs))
        else:
            call_repr = static_fn_repr
        
        try:
            log.debug("calling %s", call_repr)
            result = fn(*args, **kwargs)
        except Exception as e:
            log.debug("exception raised in %s", call_repr)
            raise
        log.debug("%s -> %r", call_repr, result)
        return result
    
    return wrapper

@contextmanager
def _sublogger(child_name: str, base: Optional[logging.Logger] = None, *, level: str = 'debug', section: Optional[str] = None):
    if base is None:
        base = _log
    logger = base.getChild(child_name)
    logger.note = getattr(logger, level)
    
    if section is not None:
        logger.note("----- BEGIN {} -----".format(section.upper()))
    
    yield logger
    
    if section is not None:
        logger.note("----- END {} -----".format(section.upper()))

class BackupFacilitator:
    """Base class for tools that upload backup objects to S3"""
    def __init__(self, bucket: str, *,
        retain_until: Optional[datetime] = None, # supercedes retention_period
        retention_period: Optional[timedelta] = None,
        use_host_prefix: bool = True,
        host: Optional[str] = None,
    ):
        super().__init__()
        self._bucket = bucket
        self.retain_until = retain_until or (
            datetime.now() + (retention_period or timedelta(days=14))
        )
        self.use_host_prefix = use_host_prefix or bool(host)
        if self.use_host_prefix:
            self._host = str(host) or socket.gethostname()
    
    @property
    def bucket(self):
        return self._bucket
    
    def _hostify(self, s):
        if not self.use_host_prefix:
            return s
        return '-'.join((self._host, s))
    
    def _retention_args(self, *, prefix=''):
        return dict(zip(
            (prefix + k for k in ('Mode', 'RetainUntilDate')),
            ('GOVERNANCE', self.retain_until)
        ))

class S3IntegrityHasher:
    """MD5 calculator for S3 upload requests
    
    Use an instance of this class like a :mod:`hashlib` hasher (except it
    doesn't accept initial content in the constructor).  Typically, this will
    be passed to a :class:`.FileHasher` used to consume a file (or file-like
    object).
    """
    def __init__(self, ):
        super().__init__()
        self._hasher = hashlib.md5()
    
    def update(self, content):
        self._hasher.update(content)
    
    def digest(self, ):
        return self._hasher.digest()
    
    def hexdigest(self, ):
        return self._hasher.hexdigest()
    
    def aws_integrity(self, ):
        return b64encode(self.digest()).decode('ascii')

class FileHasher:
    """Utility class for computing one or more hashes of a file
    
    Typical usage of an instance is to call :meth:`consume`, passing a
    file-like object (like :class:`io.BufferedReader`) that supports a
    ``read`` method returning :class:`bytes` and a chunk size for reading.
    """
    def __init__(self, *hashers):
        super().__init__()
        self.hashers = list(hashers)
    
    def update(self, chunk):
        for h in self.hashers:
            h.update(chunk)
    
    def digest_next(self, file, byte_count):
        content = file.read(byte_count)
        if len(content) == 0:
            return False
        self.update(content)
        return True
    
    def consume(self, file, chunksize):
        while self.digest_next(file, chunksize):
            pass
    
    def __getitem__(self, n):
        return self.hashers[n]

def is_aws_error(e, err_code):
    """Test for a particular AWS/boto3 error name"""
    try:
        return e.response['Error']['Code'] == err_code
    except Exception:
        return False

def namedtuple_def(fn=None, **kwargs):
    """Decorator for defining a :func:`collections.namedtuple` in a DRY way
    
    When used as a function decorator, the function body is called without
    arguments to obtain the list of fields (which are passed as *field_names*
    to :func:`collections.namedtuple`).
    
    Used as a class decorator, an instance of the defined class is constructed
    without arguments and the *instance* is used as the list of fields; it is
    therefore wise to derive the decorated class from :class:`list` or
    :class:`tuple` and initialize the field list in ``__init__`` via
    ``super().__init__``.  Additionally, attribute lookup falls back to the
    decorated class, essentially putting the decorated class at the bottom of
    the method resolution chain.
    
    In both usages, if *fn* has a docstring, that docstring is appended to the
    one generated by :func:`collections.namedtuple`.
    """
    if fn is None and not kwargs:
        if not kwargs:
            raise ValueError("Either call on a function, pass keywords, or both")
        return functools.partial(namedtuple, **kwargs)
    fields = fn()
    kwargs['module'] = fn.__module__
    result = namedtuple(fn.__qualname__, fields, **kwargs)
    if fn.__doc__ is not None:
        result.__doc__ = result.__doc__ + "\n\n" + fn.__doc__
    if hasattr(fn, '__mro__'):
        def template_lookup(self, name):
            fn_val = getattr(fn, name)
            if callable(fn_val) and not hasattr(fn_val, '__mro__'):
                fn_val = functools.partial(fn_val, self)
            return fn_val
        result.__getattr__ = template_lookup
    return result

def as_attr(obj, attr_name: str):
    def decorator(fn):
        attr_val = fn
        setattr(obj, attr_name, attr_val)
        fn.__module__ = obj.__module__
        fn.__qualname__ = obj.__qualname__ + '.' + attr_name
        return fn
    
    return decorator

@contextmanager
def value(v):
    """Syntax sugar for an indented block using a name for a value"""
    yield v
