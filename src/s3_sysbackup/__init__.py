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

"""Flexible S3-Backed Backup System for Linux

"""

from .version import __version__
import logging
try:
    # Import top-level exports here
    
    def Saver(*args, **kwargs):
        """Construct a :class:`.saver.Saver`
        
        This does a defered import to avoid loading unnecessary libraries
        """
        from . import saver
        return saver.Saver(*args, **kwargs)
    
    
    
except ImportError as e:
    logging.getLogger(__name__).warn(
        "While importing %r, could not import %r; some functionality may be unavailable",
        __name__,
        e.name,
    )
