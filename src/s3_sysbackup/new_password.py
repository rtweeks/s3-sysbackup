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
from collections import deque
from colors import color as termstyle, ansilen as plain_len
from contextlib import contextmanager
import os
import re
from select import select as fd_select
import sys
import termios
import tty

SHIFT_MOD = 1
CTRL_MOD = 2
ALT_MOD = 4

UTF8_LEADING = {
    0xC0: 2, 0xC8: 2, 0xD0: 2, 0xD8: 2,
    0xE0: 3, 0xE8: 3,
    0xF0: 4,
}

PLAIN_CHAR = re.compile("(?P<ctrl>(?:\x1b\\[(?:K|.*?m))*)(?P<ch>.|$)")

class ConsolePasswordEntry:
    def __init__(self, ):
        super().__init__()
        self._buffer = deque((), 10)
    
    def _read_keystroke(self, ):
        def get(n):
            buffered = b''
            while len(self._buffer) > 0 and n > 0:
                buffered += bytes((self._buffer.popleft(),))
                n -= 1
            if n <= 0:
                return buffered
            return buffered + os.read(sys.stdin.fileno(), n)
        get.available = lambda: bool(
            select([sys.stdin.fileno()], [], [], 0)[0]
        )
        
        def read_escseq():
            if not get.available():
                return
            b = get(2)
            if len(b) == 0:
                return
            if len(b) == 1:
                return
            if b[:1] == b'[': # CSI
                while b[-1:] not in b'~ABCDHF':
                    if not get.available():
                        break
                    nb = get(1)
                    if len(nb) == 0:
                        break
                    b += nb
                
            elif b[:1] == b'O' and get.available(): # SS3
                get(1)
        
        b = get(1)
        if len(b) == 0:
            return b''
        if b == b'\x1b':
            read_escseq()
            return None
        elif b[0] & 0xF8 in UTF8_LEADING: # UTF-8 lead byte
            n = UTF8_LEADING[b[0] & 0xF8] - 1
            while n > 0:
                nb = get(1)
                if len(nb) == 0:
                    return '\ufffd'.encode('utf-8')
                if nb[0] & 0xC0 != 0x80:
                    self._buffer.append(nb[0])
                    return '\ufffd'.encode('utf-8')
                b += nb
                n -= 1
        elif b[0] & 0xC0 == 0x80: # UTF-8 trailing byte
            return '\xfffd'.encode('utf-8')
        
        return b
    
    def read(self, prompt='Password: ', *, partial=None, on_error=None):
        password = ''
        self._prompt = prompt
        try:
            print(prompt, end='', flush=True)
            self._last_prompt_size = plain_len(prompt)
            with stdin_cbreak_mode():
                while True:
                    ks = self._read_keystroke()
                    
                    if ks is None:
                        if callable(on_error):
                            on_error("Keystroke ignored")
                        continue
                    if ks in (b'', b'\r', b'\n'):
                        print()
                        return password
                    if ks == b'\x7f': # Backspace
                        password = password[:-1]
                    elif ks == b'\x15': # Ctrl-U -- delete entire password
                        password = ''
                    elif ks[0] < 0x20:
                        if callable(on_error):
                            on_error("Keystroke ignored")
                        continue
                    else:
                        password += ks.decode('utf-8')
                    if callable(partial):
                        partial(password)
        finally:
            del self._prompt
            del self._last_prompt_size
    
    def extend_prompt(self, suffix):
        print("\r" + " " * self._last_prompt_size, end='', flush=True)
        full_prompt = self._prompt + suffix
        full_prompt_len = plain_len(full_prompt)
        prompt_max_len = os.get_terminal_size().columns - 1
        if full_prompt_len > prompt_max_len:
            shortend_prompt = ''
            shortend_prompt_len = 0
            for chm in PLAIN_CHAR.finditer(full_prompt):
                if shortend_prompt_len < prompt_max_len:
                    shortend_prompt += chm.group(0)
                    shortend_prompt_len += len(chm.group('ch'))
                else:
                    shortend_prompt += chm.group('ctrl')
            full_prompt = shortend_prompt
            full_prompt_len = shortend_prompt_len
        self._last_prompt_size = full_prompt_len
        print("\r" + full_prompt, end='', flush=True)

@contextmanager
def stdin_cbreak_mode():
    old_ttys = termios.tcgetattr(sys.stdin)
    tty.setcbreak(sys.stdin)
    try:
        yield
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_ttys)

def main(prompt='Password: '):
    pcol = ConsolePasswordEntry()
    from password_strength import tests
    from .utils import PASSWORD_POLICY
    
    def password_partial(password):
        if len(password) == 0:
            pcol.extend_prompt('')
            return
        
        pstats = PASSWORD_POLICY.password(password)
        password_strength = (1 - pstats.weakness_factor) * pstats.strength()
        comments = [
            f"strength: {password_strength * 100:.0f}%"
        ]
        if password_strength > 0.66:
            fg = 'green'
        elif password_strength > 0.45:
            fg = 'yellow'
        else:
            fg = 'red'
        
        for failure in pstats.test():
            fg = 'red'
            if isinstance(failure, tests.Length):
                comments.append(f"must be at least {failure.args[0]} characters")
            elif isinstance(failure, tests.Uppercase):
                comments.append(f"must have at least {failure.args[0]} capitals")
            elif isinstance(failure, tests.Numbers):
                comments.append(f"must have at least {failure.args[0]} numbers")
            elif isinstance(failure, tests.Special):
                comments.append(f"must have at least {failuire.args[0]} symbol characters")
            elif isinstance(failure, tests.Strength):
                comments.append(f"not strong enough")
            else:
                comments.append(f"needs {failure!r}")
        comments_str = ', '.join(comments)
        pcol.extend_prompt(termstyle(f"({comments_str})", fg=fg, style='faint'))
        # print(f"\rPassword: ({comments_str})", end='', flush=True)
    
    def password_error(message):
        pcol.extend_prompt(termstyle(f"({message})", fg='black', bg='red'))
        # print(f"\rPassword: ({message})", end='', flush=True)
    
    return pcol.read(prompt, partial=password_partial, on_error=password_error)

if __name__ == '__main__':
    main()
